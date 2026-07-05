
const NETWORK_KINDS = new Set([
  'port_scan', 'suspicious_port', 'unauthorized_flow',
  'policy_blocked', 'suspicious_bind',
  'unexpected_listen',
]);

const EVIL_KINDS = new Set([
  'process_injection', 'kernel_module_load', 'ebpf_load',
  'fileless_exec', 'container_escape', 'privilege_escalation',
  'raw_socket', 'io_uring', 'unexpected_binary', 'binary_tampering',
]);

const HONEYPOT_KINDS = new Set(['honeypot_probe']);

const KIND_META = {
  port_scan:          { label: 'Port Scan',          color: 'warning', icon: '⟳', group: 'network',
    desc: 'A process connects to many ports on one host in a short window — port scanning.' },
  suspicious_port:    { label: 'Suspicious Port',    color: 'warning', icon: '⚠', group: 'network',
    desc: 'connect/bind/sendto to a known-bad port (C2, mining, common backdoor ports).' },
  unauthorized_flow:  { label: 'Unauthorized Flow',  color: 'warning', icon: '⇝', group: 'network',
    desc: 'Network flow outside the learned baseline — a deployment reached somewhere it never had before.' },
  policy_blocked:     { label: 'Policy Blocked',     color: 'info',    icon: '✕', group: 'network',
    desc: 'Outbound connection denied by network policy (NetworkPolicy checker).' },
  raw_socket:         { label: 'Raw Socket',         color: 'danger',  icon: '-', group: 'evil',
    desc: 'socket() with a raw/netlink domain — raw socket: recon, iptables bypass, packet spoofing.' },
  suspicious_bind:    { label: 'Suspicious Bind',    color: 'warning', icon: '—', group: 'network',
    desc: 'A listening socket (bind) opened on a suspicious port — possible backdoor/listener.' },
  unexpected_listen:  { label: 'Unexpected Listen',  color: 'warning', icon: '↩', group: 'network',
    desc: 'An inbound connection was accepted (accept/accept4) that this pod was not expected to take.' },
  process_injection:  { label: 'Process Injection',  color: 'danger',  icon: '!', group: 'evil',
    desc: 'ptrace or process_vm_writev — writing into another process memory (code injection).' },
  kernel_module_load: { label: 'Kernel Module Load', color: 'danger',  icon: '↑', group: 'evil',
    desc: 'init_module/finit_module or insmod/modprobe/rmmod — kernel module load (rootkit risk).' },
  ebpf_load:          { label: 'eBPF Load',          color: 'danger',  icon: '*', group: 'evil',
    desc: 'A bpf() call — loading an eBPF program from a container (direct path to the host).' },
  fileless_exec:      { label: 'Fileless Exec',      color: 'danger',  icon: '~', group: 'evil',
    desc: 'memfd_create followed by execve — execution from memory with no file (fileless malware).' },
  container_escape:   { label: 'Container Escape',   color: 'danger',  icon: '⇧', group: 'evil',
    desc: 'pivot_root/unshare/setns/nsenter/chroot — attempt to break out of container isolation.' },
  privilege_escalation: { label: 'Privilege Escalation', color: 'danger', icon: '^', group: 'evil',
    desc: 'capset — Linux capability change (privilege escalation).' },
  io_uring:           { label: 'io_uring',           color: 'danger',  icon: '◎', group: 'evil',
    desc: 'io_uring_setup/enter/register — async I/O that bypasses classic syscall monitoring.' },
  unexpected_binary:  { label: 'Unexpected Binary',  color: 'warning', icon: '◇', group: 'evil',
    desc: 'A binary first seen after the deployment baseline locked — a process never observed during the learning window.' },
  binary_tampering:   { label: 'Binary Tampering',   color: 'danger',  icon: '✎', group: 'evil',
    desc: 'A system binary (/bin, /usr/bin, …) was renamed/unlinked/replaced at runtime — image drift / trojaned binary.' },
  digest_change:      { label: 'Digest Change',      color: 'danger',  icon: 'D', group: 'images',
    desc: 'A running image digest changed — possible image swap under the same tag.' },
  honeypot_probe:     { label: 'Honeypot Hit',       color: 'danger',  icon: '🍯', group: 'honeypot',
    desc: 'Someone connected to a honeypot trap — no legitimate traffic should ever reach it.' },
};

const GROUP_ORDER = ['network', 'evil', 'images', 'honeypot'];

const GROUP_META = {
  network:  { label: 'Network Syscalls', desc: 'Network syscall anomalies (connect/socket/bind/accept/sendto): scans, unexpected flows, suspicious ports.' },
  evil:     { label: 'Evil Syscalls',    desc: 'Dangerous syscalls: process injection, kernel module / eBPF loads, container escape, privilege escalation.' },
  images:   { label: 'Images',           desc: 'Runtime image swap — the digest changed while the tag stayed the same.' },
  honeypot: { label: 'Honeypot Hits',    desc: 'Honeypot trap hits — any connection is treated as suspicious.' },
};

export { NETWORK_KINDS, EVIL_KINDS, HONEYPOT_KINDS, KIND_META, GROUP_ORDER, GROUP_META };
