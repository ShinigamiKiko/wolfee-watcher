package webhook

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	scheme       = runtime.NewScheme()
	deserializer = serializer.NewCodecFactory(scheme).UniversalDeserializer()
)

type EventStore interface {
	Push(AuditEvent)
}

type EventReader interface {
	GetSince(since string) (EventPage, error)
}

type EventPage struct {
	Events []AuditEvent `json:"events"`
	LastID string       `json:"lastId"`
}

type Evaluator interface {
	Evaluate(ev AuditEvent)
}

type eventForwarder interface {
	Forward(events []json.RawMessage)
}

type Handler struct {
	store     EventStore
	reader    EventReader
	evaluator Evaluator
	forwarder eventForwarder
}

func NewHandler(s EventStore, r EventReader) *Handler {
	return &Handler{store: s, reader: r}
}

func (h *Handler) SetEvaluator(e Evaluator) { h.evaluator = e }

func (h *Handler) SetForwarder(f eventForwarder) { h.forwarder = f }

func (h *Handler) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	h.handleAdmission(w, r)
}

func (h *Handler) HandleEvents(w http.ResponseWriter, r *http.Request) {
	h.handleAdmission(w, r)
}

func (h *Handler) handleAdmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if _, _, err := deserializer.Decode(body, nil, &review); err != nil {
		if jsonErr := json.Unmarshal(body, &review); jsonErr != nil {
			log.Printf("[sentry-audit] decode error: %v", err)
			http.Error(w, "decode error", http.StatusBadRequest)
			return
		}
	}

	req := review.Request
	if req == nil {
		http.Error(w, "empty request", http.StatusBadRequest)
		return
	}

	ev := fromAdmissionRequest(req)
	h.store.Push(ev)
	if h.evaluator != nil {
		h.evaluator.Evaluate(ev)
	}
	if h.forwarder != nil {
		if raw, err := json.Marshal(ev); err == nil {
			h.forwarder.Forward([]json.RawMessage{raw})
		}
	}
	log.Printf("[sentry-audit] %s %s/%s by %s", ev.Kind, ev.Namespace, ev.Name, ev.User)

	resp := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) HandleGetEvents(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	if since == "" {
		since = "0"
	}
	page, err := h.reader.GetSince(since)
	if err != nil {
		log.Printf("[sentry-audit] GetSince error: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(page)
}
