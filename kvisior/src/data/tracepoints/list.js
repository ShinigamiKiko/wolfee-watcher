export const TRACEPOINT_EVENTS = [
  { name: 'sched_process_exec', sev: 'high',     cat: 'tracepoint', desc: 'Process exec via scheduler hook — catches exec through /proc/fd' },
  { name: 'sched_process_fork', sev: 'high',     cat: 'tracepoint', desc: 'Process forked a child — the process tree / spawn edge' },
  { name: 'sched_process_exit', sev: 'low',      cat: 'tracepoint', desc: 'Process exited — closes the fork/exec lifecycle' },
  { name: 'task_rename',        sev: 'medium',   cat: 'tracepoint', desc: 'Task renamed its comm — process masquerading' },
  { name: 'sched_switch',       sev: 'low',      cat: 'tracepoint', desc: 'CPU task switch — pure scheduler event, extremely high volume' },
  { name: 'module_load',        sev: 'critical', cat: 'tracepoint', desc: 'Kernel module inserted — fires on any load path (init_module, finit_module, usermode helper)' },
  { name: 'module_free',        sev: 'high',     cat: 'tracepoint', desc: 'Kernel module unloaded — rootkit covering its tracks' },
];

export const TRACEPOINT_EVENT_NAMES = TRACEPOINT_EVENTS.map(t => t.name);
export const TRACEPOINT_BY_NAME = Object.fromEntries(TRACEPOINT_EVENTS.map(t => [t.name, t]));
