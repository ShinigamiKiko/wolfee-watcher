package jobs

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	Namespace  = "wolfee-watcher"
	JobTimeout = 5 * time.Minute
	PollTick   = 3 * time.Second
	ttl        = int32(600)

	auditRunnerImage = "localhost/wolfee-watcher/audit-runner:latest"

	kubeHunterImage = "aquasec/kube-hunter:0.6.8"
)

type Runner struct {
	client kubernetes.Interface
}

func New(client kubernetes.Interface) *Runner {
	return &Runner{client: client}
}

func (r *Runner) RunBench(ctx context.Context, runID string) (string, error) {
	name := fmt.Sprintf("audit-bench-%s", runID)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: Namespace,
			Labels: map[string]string{"app": "audit-runner", "tool": "kube-bench"},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: int32ptr(ttl),
			BackoffLimit:            int32ptr(0),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: "audit-runner",
					Containers: []corev1.Container{{
						Name:            "bench",
						Image:           auditRunnerImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/tools/kube-bench", "--config-dir", "/tools/cfg", "--json"},
					}},
				},
			},
		},
	}
	return r.run(ctx, job)
}

func (r *Runner) RunHunter(ctx context.Context, runID string) (string, error) {
	name := fmt.Sprintf("audit-hunter-%s", runID)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: Namespace,
			Labels: map[string]string{"app": "audit-runner", "tool": "kube-hunter"},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: int32ptr(ttl),
			BackoffLimit:            int32ptr(0),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name:            "hunter",
						Image:           kubeHunterImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            []string{"--pod", "--report", "json", "--log", "none"},
					}},
				},
			},
		},
	}
	return r.run(ctx, job)
}

func (r *Runner) run(ctx context.Context, job *batchv1.Job) (string, error) {
	ns, name := job.Namespace, job.Name

	if err := r.client.BatchV1().Jobs(ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !kerrors.IsNotFound(err) {
		log.Printf("[jobs] pre-delete %s: %v", name, err)
	}
	time.Sleep(500 * time.Millisecond)

	_, err := r.client.BatchV1().Jobs(ns).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create job %s: %w", name, err)
	}
	log.Printf("[jobs] started %s", name)

	tctx, cancel := context.WithTimeout(ctx, JobTimeout)
	defer cancel()

	podName, err := r.waitForPod(tctx, ns, name)
	if err != nil {
		return "", err
	}
	if err := r.waitForCompletion(tctx, ns, podName); err != nil {
		return "", err
	}
	return r.collectLogs(ctx, ns, podName)
}

func (r *Runner) waitForPod(ctx context.Context, ns, jobName string) (string, error) {
	t := time.NewTicker(PollTick)
	defer t.Stop()
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for pod of %s after %d attempts", jobName, attempt)
		case <-t.C:
			attempt++
			pods, err := r.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
				LabelSelector: fmt.Sprintf("job-name=%s", jobName),
			})
			if err != nil {
				log.Printf("[jobs] waitForPod %s attempt %d: list error: %v", jobName, attempt, err)
				continue
			}
			log.Printf("[jobs] waitForPod %s attempt %d: found %d pods", jobName, attempt, len(pods.Items))
			if len(pods.Items) > 0 {
				pod := pods.Items[0]
				log.Printf("[jobs] pod %s phase=%s", pod.Name, pod.Status.Phase)
				return pod.Name, nil
			}
		}
	}
}

func (r *Runner) waitForCompletion(ctx context.Context, ns, podName string) error {
	t := time.NewTicker(PollTick)
	defer t.Stop()
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for pod %s to complete after %d attempts", podName, attempt)
		case <-t.C:
			attempt++
			pod, err := r.client.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
			if err != nil {
				log.Printf("[jobs] waitForCompletion %s attempt %d: get error: %v", podName, attempt, err)
				continue
			}
			log.Printf("[jobs] pod %s phase=%s attempt=%d", podName, pod.Status.Phase, attempt)
			for _, cs := range pod.Status.ContainerStatuses {
				log.Printf("[jobs]   container %s ready=%v state=%+v", cs.Name, cs.Ready, cs.State)
			}
			if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
				return nil
			}
		}
	}
}

func (r *Runner) collectLogs(ctx context.Context, ns, podName string) (string, error) {

	time.Sleep(2 * time.Second)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req := r.client.CoreV1().Pods(ns).GetLogs(podName, &corev1.PodLogOptions{})
		stream, err := req.Stream(ctx)
		if err != nil {
			lastErr = fmt.Errorf("logs attempt %d: %w", attempt, err)
			log.Printf("[jobs] log attempt %d failed for %s: %v", attempt, podName, err)
			time.Sleep(2 * time.Second)
			continue
		}

		var sb strings.Builder
		buf := make([]byte, 8192)
		for {
			n, readErr := stream.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				lastErr = readErr
				break
			}
		}
		stream.Close()

		result := sb.String()
		log.Printf("[jobs] collected %d bytes from %s (attempt %d)", len(result), podName, attempt)
		if len(result) > 0 {
			return result, nil
		}

		log.Printf("[jobs] empty logs from %s, retrying…", podName)
		time.Sleep(2 * time.Second)
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("pod %s produced no output after 3 attempts", podName)
}

func int32ptr(i int32) *int32 { return &i }
