package logtail

import (
	"encoding/json"
	"net/url"
	"strconv"
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
	ImpersonatedUser *struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"impersonatedUser"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource        string `json:"resource"`
		Namespace       string `json:"namespace"`
		Name            string `json:"name"`
		Subresource     string `json:"subresource"`
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code    int32 `json:"code"`
		Details *struct {
			UID string `json:"uid"`
		} `json:"details"`
	} `json:"responseStatus"`
	RequestObject  json.RawMessage `json:"requestObject"`
	ResponseObject *struct {
		Metadata struct {
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	} `json:"responseObject"`
	RequestReceivedTimestamp time.Time         `json:"requestReceivedTimestamp"`
	StageTimestamp           time.Time         `json:"stageTimestamp"`
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

var humanSystemUsers = map[string]bool{"system:admin": true}

var watchedResources = map[string]bool{
	"mutatingwebhookconfigurations":   true,
	"validatingwebhookconfigurations": true,
}

func isPerson(user string) bool {
	return user != "" && (humanSystemUsers[user] || !strings.HasPrefix(user, "system:"))
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func dryRun(uri string) bool {
	i := strings.IndexByte(uri, '?')
	if i < 0 {
		return false
	}
	query, err := url.ParseQuery(uri[i+1:])
	return err == nil && len(query["dryRun"]) > 0
}

func (a *apiEvent) identify(ev *webhook.AuditEvent) {
	var response, removed, replaced, previous string
	if a.ResponseObject != nil {
		response = a.ResponseObject.Metadata.UID
		if ev.Kind != webhook.EventKindDelete {
			ev.ResourceVersion = a.ResponseObject.Metadata.ResourceVersion
		}
	}
	if a.ResponseStatus != nil && a.ResponseStatus.Details != nil {
		removed = a.ResponseStatus.Details.UID
	}
	if a.Verb == "update" {
		replaced = a.ObjectRef.UID
		if n, err := strconv.ParseUint(a.ObjectRef.ResourceVersion, 10, 64); err != nil || n != 0 {
			previous = a.ObjectRef.ResourceVersion
		}
	}
	ev.UID = first(a.Annotations[webhook.ObjectUIDAnnotation], response, removed, replaced)
	if !a.StageTimestamp.IsZero() {
		ev.CompletedAt = &a.StageTimestamp
	}
	if ev.Kind == webhook.EventKindUpdate {
		ev.PrevResourceVersion = first(a.Annotations[webhook.PreviousRevisionAnnotation], previous)
	}
	ev.Unchanged = ev.DryRun || a.Annotations[webhook.ChangedAnnotation] == "false" ||
		(ev.ResourceVersion != "" && ev.ResourceVersion == ev.PrevResourceVersion)
}

func (f Filter) Parse(line []byte) (Record, bool) {
	var a apiEvent
	if err := json.Unmarshal(line, &a); err != nil {
		return Record{}, false
	}
	if a.ObjectRef == nil || a.ObjectRef.Resource == "" {
		return Record{}, false
	}
	ref := a.ObjectRef
	kind, ok := eventKind(a.Verb, ref.Subresource)
	if !ok {
		return Record{}, false
	}
	connect := kind == webhook.EventKindExec || kind == webhook.EventKindAttach || kind == webhook.EventKindPortForward
	switch a.Stage {
	case "ResponseComplete":
	case "ResponseStarted":
		if !connect {
			return Record{}, false
		}
	default:
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
		DryRun:     dryRun(a.RequestURI),
		Allowed:    code < 400,
		StatusCode: code,
		AuditID:    a.AuditID,
	}
	if kind == webhook.EventKindDelete && len(a.RequestObject) > 0 {
		var options struct {
			DryRun []string `json:"dryRun"`
		}
		if json.Unmarshal(a.RequestObject, &options) == nil && len(options.DryRun) > 0 {
			ev.DryRun = true
		}
	}
	if a.ImpersonatedUser != nil && a.ImpersonatedUser.Username != "" {
		ev.ImpersonatedUser = a.ImpersonatedUser.Username
		ev.ImpersonatedGroups = a.ImpersonatedUser.Groups
	}

	for key, uid := range a.Annotations {
		if strings.HasSuffix(key, eventIDAnnotation) && uid != "" {
			return Record{EventUID: uid, Event: ev}, true
		}
	}

	if code >= 400 && code != 401 && code != 403 {
		return Record{}, false
	}
	if ref.Subresource != "" && !connect {
		if ref.Subresource == "status" {
			return Record{}, false
		}
		ev.Resource = ref.Resource + "/" + ref.Subresource
	}
	watched := watchedResources[ref.Resource] && ref.Subresource == "" && !isRead(kind) && code < 400
	if watched {
		a.identify(&ev)
	}
	if matchAny(f.DropResources, ref.Resource) || (!watched && matchAny(f.DropUsers, ev.User)) {
		return Record{}, false
	}
	if isRead(kind) && !isPerson(ev.User) && ref.Resource != "secrets" {
		return Record{}, false
	}
	return Record{Event: ev}, true
}
