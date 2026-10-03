package logtail

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/wolfee-watcher/sentry-audit/internal/webhook"
)

const eventIDAnnotation = "/" + webhook.EventIDAnnotation

type apiEvent struct {
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	Verb       string `json:"verb"`
	RequestURI string `json:"requestURI"`
	User       struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int32 `json:"code"`
	} `json:"responseStatus"`
	RequestReceivedTimestamp time.Time         `json:"requestReceivedTimestamp"`
	Annotations              map[string]string `json:"annotations"`
}

type Record struct {
	EventUID string             `json:"eventUid,omitempty"`
	Event    webhook.AuditEvent `json:"event"`
}

type Filter struct {
	DropResources []string
	DropUsers     []string
}

func DefaultFilter() Filter {
	return Filter{
		DropResources: []string{
			"leases", "events", "endpoints", "endpointslices",
			"tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews",
			"selfsubjectrulesreviews", "localsubjectaccessreviews",
		},
		DropUsers: []string{
			"system:node:*", "system:kube-*", "system:apiserver", "system:anonymous",
			"system:serviceaccount:kube-system:*",
		},
	}
}

func glob(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if glob(p, s) {
			return true
		}
	}
	return false
}

func eventKind(verb, subresource string) (webhook.EventKind, bool) {
	switch subresource {
	case "exec":
		return webhook.EventKindExec, true
	case "attach":
		return webhook.EventKindAttach, true
	case "portforward":
		return webhook.EventKindPortForward, true
	}
	switch verb {
	case "create":
		return webhook.EventKindCreate, true
	case "update", "patch":
		return webhook.EventKindUpdate, true
	case "delete", "deletecollection":
		return webhook.EventKindDelete, true
	case "get":
		return webhook.EventKindGet, true
	case "list":
		return webhook.EventKindList, true
	}
	return webhook.EventKindUnknown, false
}

func isRead(k webhook.EventKind) bool {
	return k == webhook.EventKindGet || k == webhook.EventKindList
}

func isPerson(user string) bool {
	return user != "" && !strings.HasPrefix(user, "system:")
}

func (f Filter) Parse(line []byte) (Record, bool) {
	var a apiEvent
	if err := json.Unmarshal(line, &a); err != nil {
		return Record{}, false
	}
	if a.Stage != "ResponseComplete" || a.ObjectRef == nil || a.ObjectRef.Resource == "" {
		return Record{}, false
	}
	ref := a.ObjectRef
	kind, ok := eventKind(a.Verb, ref.Subresource)
	if !ok {
		return Record{}, false
	}
	code := int32(0)
	if a.ResponseStatus != nil {
		code = a.ResponseStatus.Code
	}
	ts := a.RequestReceivedTimestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	ev := webhook.AuditEvent{
		ID:         a.AuditID,
		Timestamp:  ts,
		User:       a.User.Username,
		Groups:     a.User.Groups,
		SourceIPs:  a.SourceIPs,
		UserAgent:  a.UserAgent,
		Kind:       kind,
		Resource:   ref.Resource,
		Namespace:  ref.Namespace,
		Name:       ref.Name,
		Allowed:    code != 401 && code != 403,
		StatusCode: code,
		AuditID:    a.AuditID,
	}

	for key, uid := range a.Annotations {
		if strings.HasSuffix(key, eventIDAnnotation) && uid != "" {
			return Record{EventUID: uid, Event: ev}, true
		}
	}

	connect := kind == webhook.EventKindExec || kind == webhook.EventKindAttach || kind == webhook.EventKindPortForward
	if ref.Subresource != "" && !connect {
		if ref.Subresource == "status" {
			return Record{}, false
		}
		ev.Resource = ref.Resource + "/" + ref.Subresource
	}
	if matchAny(f.DropResources, ref.Resource) || matchAny(f.DropUsers, ev.User) {
		return Record{}, false
	}
	if isRead(kind) && !isPerson(ev.User) && ref.Resource != "secrets" {
		return Record{}, false
	}
	return Record{Event: ev}, true
}
