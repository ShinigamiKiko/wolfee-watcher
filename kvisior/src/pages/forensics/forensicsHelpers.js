import { useState, useCallback } from 'react';
import { TRACEPOINT_NAMES } from '../tracepoints/tracepointsCatalog';

const FNS_SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };

const DEFAULT_SEVERITY = {
  critical: ['ptrace','process_vm_writev','memfd_create','bpf','init_module','finit_module','pivot_root','unshare','setns'],
  high:     ['socket','mmap','mprotect','chroot','mount','umount2','security_sb_mount','dup2','dup3'],
  medium:   ['connect','bind','open','openat','openat2','setuid','setgid','setreuid','setresuid','setresgid','capset'],
  low:      ['security_bprm_check'],
  binaries: { critical: [], high: [], medium: [], low: [] },
};

export const SYSCALL_GROUPS = {
  'Process':   ['execve','execveat','sched_process_exec','security_bprm_check'],
  'Network':   ['socket','connect','bind','accept','sendto','recvfrom'],
  'Security':  ['ptrace','process_vm_writev','memfd_create','bpf','io_uring_setup','io_uring_enter','io_uring_register','mmap','mprotect','init_module','finit_module'],
  'Filesystem':['open','openat','openat2','read','write','unlink','rename','chmod'],
  'Privilege': ['setuid','setgid','setreuid','setresuid','setresgid','capset'],
  'Escape':    ['pivot_root','unshare','setns','chroot','mount','umount2','security_sb_mount'],
};

export const BINARY_CALL_SYSCALLS = new Set(['execve', 'execveat']);

export function isBinaryCall(syscall) {
  return BINARY_CALL_SYSCALLS.has(syscall);
}

const TRACEPOINT_SET = new Set(TRACEPOINT_NAMES);

export function isLsmHook(syscall) {
  return typeof syscall === 'string' && syscall.startsWith('security_');
}

export function isTracepoint(syscall) {
  return TRACEPOINT_SET.has(syscall);
}

export function isForensicEvent(syscall) {
  return isBinaryCall(syscall);
}

export function eventKind(syscall) {
  if (isLsmHook(syscall)) return 'lsm';
  if (isTracepoint(syscall)) return 'tracepoint';
  return 'syscall';
}

export const KIND_LABEL = {
  syscall:    'Syscall',
  tracepoint: 'Tracepoint',
  lsm:        'LSM Hook',
};

function loadSevConfig() {
  try {
    const saved = localStorage.getItem('sw_severity');
    if (saved) {
      const parsed = JSON.parse(saved);
      if (!parsed.binaries) parsed.binaries = { critical: [], high: [], medium: [], low: [] };
      return parsed;
    }
  } catch {}
  return JSON.parse(JSON.stringify(DEFAULT_SEVERITY));
}

export function useSeverityConfig() {
  const [config, setConfig] = useState(loadSevConfig);
  const save = useCallback((next) => {
    setConfig(next);
    localStorage.setItem('sw_severity', JSON.stringify(next));
  }, []);

  const getSev = useCallback((syscall, execpath, process) => {
    if (isBinaryCall(syscall)) {
      const name = (execpath || process || '').toLowerCase();
      const bins = config.binaries || { critical: [], high: [], medium: [], low: [] };
      for (const sev of ['critical','high','medium','low']) {
        for (const b of (bins[sev] || [])) {
          if (name && name.includes(b.toLowerCase())) return sev;
        }
      }
      return 'none';
    }
    for (const sev of ['critical','high','medium','low']) {
      if (config[sev].includes(syscall)) return sev;
    }
    return 'none';
  }, [config]);

  return { config, save, getSev };
}
