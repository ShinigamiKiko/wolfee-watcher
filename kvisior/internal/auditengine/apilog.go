package auditengine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/wolfee-watcher/pkg/auditrules"
)

func apiLogEventID(ev *auditrules.Event) string {
	identity := struct {
		AuditID, Received, User, ImpersonatedUser, UserAgent, Kind, Resource, Namespace, Name, Container string
		Groups, ImpersonatedGroups, SourceIPs, Commands                                                  []string
		Ports                                                                                            []int32
		DryRun                                                                                           bool
	}{
		AuditID: ev.AuditID, Received: ev.Timestamp.UTC().Format(time.RFC3339Nano),
		User: ev.User, ImpersonatedUser: ev.ImpersonatedUser, Kind: ev.Kind,
		Resource: ev.Resource, Namespace: ev.Namespace, Name: ev.Name,
		UserAgent: ev.UserAgent, Groups: ev.Groups, ImpersonatedGroups: ev.ImpersonatedGroups,
		SourceIPs: ev.SourceIPs, Commands: ev.Commands, Container: ev.Container, Ports: ev.Ports, DryRun: ev.DryRun,
	}
	raw, _ := json.Marshal(identity)
	return fmt.Sprintf("apilog-sha256:%x", sha256.Sum256(raw))
}
