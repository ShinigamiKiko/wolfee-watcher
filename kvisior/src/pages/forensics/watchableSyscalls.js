export const SYSCALL_GROUPS = [
  {
    label: 'Process & Memory',
    items: [
      { name: 'ptrace',           desc: 'Attach to / inspect another process — debuggers and code injection.' },
      { name: 'process_vm_writev', desc: 'Write directly into another process memory — injection technique.' },
      { name: 'memfd_create',     desc: 'Create an anonymous in-memory file — fileless malware staging.' },
      { name: 'bpf',              desc: 'Load eBPF programs — kernel-level hooking / rootkits.' },
      { name: 'mmap',             desc: 'Map memory regions — RWX maps used for shellcode.' },
      { name: 'mprotect',         desc: 'Change memory protection — flip pages to executable.' },
    ],
  },
  {
    label: 'Async I/O (io_uring)',
    items: [
      { name: 'io_uring_setup',    desc: 'Create an io_uring instance — async I/O ring that bypasses per-syscall monitoring.' },
      { name: 'io_uring_enter',    desc: 'Submit/complete io_uring operations — read/write/connect/send without the matching syscalls.' },
      { name: 'io_uring_register', desc: 'Register buffers/files with an io_uring — staging for async I/O evasion.' },
    ],
  },
  {
    label: 'Network',
    items: [
      { name: 'socket',  desc: 'Create a network socket — outbound connections / C2.' },
      { name: 'connect', desc: 'Initiate an outbound connection to a remote host.' },
      { name: 'bind',    desc: 'Bind a socket to a port — listeners / backdoors.' },
      { name: 'accept',  desc: 'Accept an incoming connection on a listening socket.' },
      { name: 'accept4', desc: 'Accept an incoming connection (with flags).' },
      { name: 'sendto',  desc: 'Send data on a socket — exfiltration / beaconing.' },
    ],
  },
  {
    label: 'Filesystem',
    items: [
      { name: 'open',    desc: 'Open a file — access to sensitive paths.' },
      { name: 'openat',  desc: 'Open a file relative to a directory fd.' },
      { name: 'openat2', desc: 'Open a file with extended how-flags.' },
    ],
  },
  {
    label: 'Container Escape',
    items: [
      { name: 'mount',             desc: 'Mount a filesystem — host path exposure / escape.' },
      { name: 'umount2',           desc: 'Unmount a filesystem.' },
      { name: 'security_sb_mount', desc: 'LSM hook fired on every mount attempt.' },
      { name: 'pivot_root',        desc: 'Change the root mount — namespace / container escape.' },
      { name: 'unshare',           desc: 'Detach into new namespaces — privilege/namespace manipulation.' },
      { name: 'setns',             desc: 'Join an existing namespace — cross-namespace access.' },
      { name: 'chroot',            desc: 'Change apparent root directory.' },
    ],
  },
  {
    label: 'Privilege',
    items: [
      { name: 'setuid',     desc: 'Set user ID — privilege change (often to root).' },
      { name: 'setgid',     desc: 'Set group ID — privilege change.' },
      { name: 'setreuid',   desc: 'Set real and effective user IDs.' },
      { name: 'setresuid',  desc: 'Set real, effective and saved user IDs.' },
      { name: 'setresgid',  desc: 'Set real, effective and saved group IDs.' },
      { name: 'capset',     desc: 'Set process capabilities — privilege escalation.' },
    ],
  },
  {
    label: 'Redirection & Modules',
    items: [
      { name: 'dup2',         desc: 'Duplicate a file descriptor — shell stdio redirection.' },
      { name: 'dup3',         desc: 'Duplicate a file descriptor (with flags).' },
      { name: 'init_module',  desc: 'Load a kernel module — rootkit installation.' },
      { name: 'finit_module', desc: 'Load a kernel module from an fd.' },
    ],
  },
];

export const WATCHABLE_SYSCALLS = SYSCALL_GROUPS.flatMap(g => g.items.map(i => i.name));
