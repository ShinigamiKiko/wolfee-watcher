

export const SYSCALLS = [
  { name: 'execve',            sev: 'high',     cat: 'process',    desc: 'Binary execution in container' },
  { name: 'execveat',          sev: 'high',     cat: 'process',    desc: 'Binary execution via fd (execveat)' },

  { name: 'ptrace',            sev: 'critical', cat: 'security',   desc: 'Process tracing — code injection risk' },
  { name: 'process_vm_writev', sev: 'critical', cat: 'security',   desc: 'Memory write to foreign process' },
  { name: 'memfd_create',      sev: 'critical', cat: 'security',   desc: 'Anonymous in-memory file — fileless malware base primitive' },
  { name: 'bpf',               sev: 'critical', cat: 'security',   desc: 'eBPF program load from container — direct host attack vector' },
  { name: 'io_uring_setup',    cat: 'security',   desc: 'io_uring instance created — async I/O ring that bypasses per-syscall monitoring' },
  { name: 'io_uring_enter',    cat: 'security',   desc: 'io_uring submit/complete — read/write/connect/send without the matching syscalls' },
  { name: 'io_uring_register', cat: 'security',   desc: 'io_uring buffers/files registered — staging for async I/O evasion' },
  { name: 'socket',            sev: 'high',     cat: 'network',    desc: 'Socket creation: IPv4 (AF_INET), IPv6 (AF_INET6), Netlink (AF_NETLINK) — unexpected raw/netlink socket from container',
    paramType: 'socket' },
  { name: 'mmap',              sev: 'high',     cat: 'memory',     desc: 'Memory map with W|X or RWX protection (prot=6/7) — shellcode / fileless execution',
    paramType: 'prot' },
  { name: 'mprotect',          sev: 'high',     cat: 'memory',     desc: 'Memory protection change to W|X or RWX (prot=6/7) — W→X transition',
    paramType: 'prot' },

  { name: 'init_module',       sev: 'critical', cat: 'security',   desc: 'Kernel module loaded' },
  { name: 'finit_module',      sev: 'critical', cat: 'security',   desc: 'Kernel module loaded via fd (finit)' },

  { name: 'pivot_root',        sev: 'critical', cat: 'escape',     desc: 'Root pivot — container escape attempt' },
  { name: 'unshare',           sev: 'critical', cat: 'escape',     desc: 'Namespace unshare — isolation break' },
  { name: 'setns',             sev: 'critical', cat: 'escape',     desc: 'Namespace join — lateral movement' },
  { name: 'chroot',            sev: 'high',     cat: 'escape',     desc: 'Chroot — filesystem isolation change' },
  { name: 'mount',             sev: 'high',     cat: 'escape',     desc: 'Filesystem mount inside container' },
  { name: 'umount2',           sev: 'high',     cat: 'escape',     desc: 'Filesystem unmount inside container' },
  { name: 'security_sb_mount', sev: 'high',     cat: 'escape',     desc: 'Mount via LSM hook (more reliable than mount syscall)' },

  { name: 'setuid',            sev: 'high',     cat: 'privesc',    desc: 'UID change — privilege escalation' },
  { name: 'setgid',            sev: 'high',     cat: 'privesc',    desc: 'GID change — privilege escalation' },
  { name: 'setreuid',          sev: 'high',     cat: 'privesc',    desc: 'Real/effective UID change' },
  { name: 'setresuid',         sev: 'high',     cat: 'privesc',    desc: 'Real/effective/saved UID change' },
  { name: 'setresgid',         sev: 'high',     cat: 'privesc',    desc: 'Real/effective/saved GID change' },
  { name: 'capset',            sev: 'high',     cat: 'privesc',    desc: 'Linux capabilities modified' },

  { name: 'open',              sev: 'medium',   cat: 'filesystem', desc: 'Sensitive file opened (legacy open)',
    paramType: 'path' },
  { name: 'openat',            sev: 'medium',   cat: 'filesystem', desc: 'Sensitive file opened (openat)',
    paramType: 'path' },

  { name: 'connect',           sev: 'medium',   cat: 'network',    desc: 'Outbound TCP/UDP connection' },
  { name: 'bind',              sev: 'medium',   cat: 'network',    desc: 'Socket bound — unexpected listener' },
  { name: 'dup2',              sev: 'high',     cat: 'network',    desc: 'FD redirect to stdin/stdout/stderr (newfd≤2) — classic reverse shell pattern',
    paramType: 'newfd' },
  { name: 'dup3',              sev: 'high',     cat: 'network',    desc: 'FD redirect to stdin/stdout/stderr (newfd≤2) — reverse shell variant',
    paramType: 'newfd' },
];

export const PATH_PRESETS = [
  { label: '/etc/passwd',              value: '/etc/passwd',              desc: 'User accounts' },
  { label: '/etc/shadow',              value: '/etc/shadow',              desc: 'Password hashes' },
  { label: '/etc/os-release',          value: '/etc/os-release',          desc: 'OS identification — fingerprinting' },
  { label: '/var/run/secrets/*',       value: '/var/run/secrets/*',       desc: 'K8s service account tokens' },
  { label: '/run/secrets/*',           value: '/run/secrets/*',           desc: 'K8s secrets (alt path)' },
  { label: '/root/.ssh/*',             value: '/root/.ssh/*',             desc: 'Root SSH keys' },
  { label: '/root/.bashrc',            value: '/root/.bashrc',            desc: 'Root shell config' },
  { label: '/root/.bash_history',      value: '/root/.bash_history',      desc: 'Root command history' },
];

export const PROT_PRESETS = [
  { label: 'RWX (0x7)',   value: '7', desc: 'PROT_READ|WRITE|EXEC — shellcode / most dangerous' },
  { label: 'WX  (0x6)',   value: '6', desc: 'PROT_WRITE|EXEC — fileless malware pattern' },
];

export const SOCKET_PRESETS = [
  { label: 'AF_INET (2)',     value: '2',  desc: 'IPv4 — outbound connections from container' },
  { label: 'AF_INET6 (10)',   value: '10', desc: 'IPv6 — outbound connections from container' },
  { label: 'AF_NETLINK (16)', value: '16', desc: 'Netlink — network recon, iptables bypass, container escape' },
];

export const DUP_PRESETS = [
  { label: 'stdin  (0)', value: '0', desc: 'Redirect to stdin — reverse shell' },
  { label: 'stdout (1)', value: '1', desc: 'Redirect to stdout — reverse shell' },
  { label: 'stderr (2)', value: '2', desc: 'Redirect to stderr — reverse shell' },
];

export const SYSCALL_BY_NAME = Object.fromEntries(SYSCALLS.map(s => [s.name, s]));

export const SYSCALLS_BY_CAT = SYSCALLS.reduce((m, s) => {
  (m[s.cat] = m[s.cat] || []).push(s);
  return m;
}, {});

const CATEGORIES = ['process', 'security', 'memory', 'escape', 'privesc', 'filesystem', 'network'];

export const CAT_LABEL = {
  process:    'Process',
  security:   'Injection',
  memory:     'Memory',
  escape:     'Container Escape',
  privesc:    'Privilege Escalation',
  filesystem: 'File Access',
  network:    'Network',
};

export const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

const SEV_COLOR = {
  critical: 'var(--danger)',
  high:     'var(--warning)',
  medium:   '#a78bfa',
  low:      'var(--accent-3)',
};
