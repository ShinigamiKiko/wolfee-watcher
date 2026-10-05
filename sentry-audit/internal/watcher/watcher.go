package watcher

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Watcher struct {
	client kubernetes.Interface
	emit   func(webhook.AuditEvent)
	ready  atomic.Bool
}

func New(client kubernetes.Interface, emit func(webhook.AuditEvent)) *Watcher {
	return &Watcher{client: client, emit: emit}
}

func (w *Watcher) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(w.client, 0)
	mutating := factory.Admissionregistration().V1().MutatingWebhookConfigurations().Informer()
	validating := factory.Admissionregistration().V1().ValidatingWebhookConfigurations().Informer()
	mutating.AddEventHandler(w.handlers("mutatingwebhookconfigurations"))
	validating.AddEventHandler(w.handlers("validatingwebhookconfigurations"))
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), mutating.HasSynced, validating.HasSynced) {
		return ctx.Err()
	}
	w.ready.Store(true)
	<-ctx.Done()
	return ctx.Err()
}

func (w *Watcher) handlers(resource string) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if w.ready.Load() {
				w.emitEvent("create", resource, obj, "")
			}
		},
		UpdateFunc: func(old, obj interface{}) {
			if !w.ready.Load() {
				return
			}
			previous := ""
			if meta, ok := old.(metav1.Object); ok {
				previous = meta.GetResourceVersion()
			}
			if meta, ok := obj.(metav1.Object); ok && previous != "" && previous == meta.GetResourceVersion() {
				return
			}
			w.emitEvent("update", resource, obj, previous)
		},
		DeleteFunc: func(obj interface{}) {
			if w.ready.Load() {
				w.emitEvent("delete", resource, obj, "")
			}
		},
	}
}

func (w *Watcher) emitEvent(action, resource string, obj interface{}, previous string) {
	meta, ok := obj.(metav1.Object)
	if !ok {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			meta, _ = tombstone.Obj.(metav1.Object)
		}
	}
	if meta == nil {
		return
	}
	webhookType := ""
	switch resource {
	case "mutatingwebhookconfigurations":
		webhookType = "MutatingWebhookConfiguration"
	case "validatingwebhookconfigurations":
		webhookType = "ValidatingWebhookConfiguration"
	}
	w.emit(webhook.AuditEvent{
		ID:                  fmt.Sprintf("informer-%s-%s-%s-%s", resource, action, meta.GetUID(), meta.GetResourceVersion()),
		Timestamp:           time.Now().UTC(),
		User:                "unknown",
		ServiceAccount:      "unknown",
		Kind:                webhook.EventKind(action),
		Resource:            resource,
		WebhookType:         webhookType,
		Name:                meta.GetName(),
		UID:                 string(meta.GetUID()),
		ResourceVersion:     meta.GetResourceVersion(),
		PrevResourceVersion: previous,
		Source:              "kubernetes-informer",
		Allowed:             true,
	})
}
