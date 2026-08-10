package events

import "strings"

type Kind string

const (
	Syscall    Kind = "syscall"
	LSMHook    Kind = "lsm_hook"
	Tracepoint Kind = "tracepoint"
)

var tracepoints = map[string]struct{}{
	"sched_process_exec": {}, "sched_process_fork": {}, "sched_process_exit": {},
	"task_rename": {}, "sched_switch": {}, "module_load": {}, "module_free": {},
	"cgroup_mkdir": {}, "cgroup_rmdir": {}, "cgroup_attach_task": {},
}

func KindFor(name string) Kind {
	if strings.HasPrefix(name, "security_") {
		return LSMHook
	}
	if _, ok := tracepoints[name]; ok {
		return Tracepoint
	}
	return Syscall
}
