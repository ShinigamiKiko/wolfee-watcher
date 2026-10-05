package watcher

import (
	"context"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
)

func TestWatcherEmitsWebhookLifecycleAfterSync(t *testing.T) {
	client := fake.NewSimpleClientset(&admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "existing"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan webhook.AuditEvent, 10)
	w := New(client, func(event webhook.AuditEvent) { events <- event })
	go w.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !w.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !w.ready.Load() {
		t.Fatal("watcher did not synchronize")
	}

	obj, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "created", UID: "vwh-uid", ResourceVersion: "1"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertEvent(t, events, "create", "validatingwebhookconfigurations", "created")

	obj.Labels = map[string]string{"changed": "true"}
	obj.ResourceVersion = "2"
	obj, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, obj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertEvent(t, events, "update", "validatingwebhookconfigurations", "created")

	if err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, "created", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertEvent(t, events, "delete", "validatingwebhookconfigurations", "created")
}

func TestWatcherEmitsMutatingWebhookLifecycleAfterSync(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan webhook.AuditEvent, 10)
	w := New(client, func(event webhook.AuditEvent) { events <- event })
	go w.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !w.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !w.ready.Load() {
		t.Fatal("watcher did not synchronize")
	}

	obj, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(ctx, &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "created", UID: "mwh-uid", ResourceVersion: "1"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertEvent(t, events, "create", "mutatingwebhookconfigurations", "created")

	obj.Labels = map[string]string{"changed": "true"}
	obj.ResourceVersion = "2"
	obj, err = client.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(ctx, obj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertEvent(t, events, "update", "mutatingwebhookconfigurations", "created")

	if err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(ctx, "created", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertEvent(t, events, "delete", "mutatingwebhookconfigurations", "created")
}

func TestWatcherCarriesTheReplacedRevisionOnUpdate(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan webhook.AuditEvent, 10)
	w := New(client, func(event webhook.AuditEvent) { events <- event })
	go w.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !w.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !w.ready.Load() {
		t.Fatal("watcher did not synchronize")
	}

	obj, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "changed", UID: "vwh-uid", ResourceVersion: "41"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	obj.ResourceVersion = "42"
	if obj, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, "changed", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ kind, version, previous string }{{"create", "41", ""}, {"update", "42", "41"}, {"delete", "42", ""}} {
		select {
		case event := <-events:
			if string(event.Kind) != want.kind || event.ResourceVersion != want.version || event.PrevResourceVersion != want.previous {
				t.Fatalf("%s: unexpected event %+v", want.kind, event)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for %s", want.kind)
		}
	}
}

func assertEvent(t *testing.T, events <-chan webhook.AuditEvent, kind webhook.EventKind, resource, name string) {
	t.Helper()
	select {
	case event := <-events:
		webhookType := "MutatingWebhookConfiguration"
		if resource == "validatingwebhookconfigurations" {
			webhookType = "ValidatingWebhookConfiguration"
		}
		if event.Kind != kind || event.Resource != resource || event.WebhookType != webhookType || event.Name != name || event.User != "unknown" || event.ServiceAccount != "unknown" || event.Source != "kubernetes-informer" || event.Timestamp.IsZero() || event.UID == "" || event.ResourceVersion == "" {
			t.Fatalf("unexpected event: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s %s/%s", kind, resource, name)
	}
}
