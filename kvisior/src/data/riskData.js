export const RISK_DATA = [
  { name:'legacy-api',   ns:'legacy',      cluster:'prod-cluster', score:8.9, color:'var(--danger)',  label:'Critical',
    factors:[
      { name:'Policy Violations',         score:9.4, color:'var(--danger)',  detail:'12 active violations — Insecure capabilities, SSH exposed, root container' },
      { name:'Image Vulnerabilities',     score:8.7, color:'var(--danger)',  detail:'6 critical CVEs including CVE-2021-4034 (CVSS 7.8) and CVE-2022-0847' },
      { name:'Service Reachability',      score:7.2, color:'var(--warning)', detail:'Externally exposed on port 22 — Internet-facing load balancer' },
      { name:'RBAC Config',               score:6.1, color:'var(--warning)', detail:'Service account has cluster-admin binding' },
      { name:'Suspicious Process Exec',   score:4.3, color:'#a78bfa',        detail:'bash, curl detected in runtime process tree' },
      { name:'Service Config',            score:2.1, color:'var(--accent-3)', detail:'No CPU/memory limits defined' },
    ]},
  { name:'debug-tools',  ns:'default',     cluster:'dev-cluster',  score:7.4, color:'var(--warning)', label:'High',
    factors:[
      { name:'Policy Violations',         score:8.1, color:'var(--danger)',  detail:'7 violations — Privileged container, no liveness probe' },
      { name:'Suspicious Process Exec',   score:7.9, color:'var(--warning)', detail:'nmap, nc, tcpdump observed in runtime' },
      { name:'Image Vulnerabilities',     score:5.5, color:'#a78bfa',        detail:'3 high CVEs, no critical, OS not EOL' },
      { name:'Service Config',            score:3.2, color:'var(--accent-3)', detail:'No resource limits; hostPID enabled' },
    ]},
  { name:'auth-gateway', ns:'production',  cluster:'prod-cluster', score:5.8, color:'#a78bfa',        label:'Medium',
    factors:[
      { name:'Image Vulnerabilities',     score:7.4, color:'var(--warning)', detail:'7 critical CVEs in quay.io/auth/gateway:latest' },
      { name:'Policy Violations',         score:5.2, color:'#a78bfa',        detail:'4 violations — No resource limits, latest tag used' },
      { name:'Service Reachability',      score:4.0, color:'var(--accent-3)', detail:'Ingress-only; internal cluster traffic' },
    ]},
  { name:'payments-svc', ns:'production',  cluster:'prod-cluster', score:3.2, color:'var(--accent-3)', label:'Low',
    factors:[
      { name:'Policy Violations',         score:3.8, color:'var(--accent-3)', detail:'1 violation — No liveness probe' },
      { name:'Image Vulnerabilities',     score:2.9, color:'var(--accent-3)', detail:'4 medium CVEs, none critical or high' },
    ]},
  { name:'frontend',     ns:'default',     cluster:'staging',      score:2.1, color:'var(--accent-3)', label:'Low',
    factors:[
      { name:'Policy Violations',         score:2.4, color:'var(--accent-3)', detail:'1 violation — Latest image tag used' },
      { name:'Image Vulnerabilities',     score:1.8, color:'var(--accent-3)', detail:'2 low CVEs only' },
    ]},
];

function openRisk(row) {
  const id = parseInt(row.dataset.id);
  const d  = RISK_DATA[id];
  if (!d) return;
  document.querySelectorAll('.risk-row').forEach(r => r.style.background = '');
  row.style.background = 'rgba(0,200,255,.05)';
  document.getElementById('risk-dp-name').textContent = d.name;
  document.getElementById('risk-dp-meta').textContent = d.cluster + ' · ' + d.ns;
  const ring = document.getElementById('risk-dp-score-ring');
  ring.textContent = d.score;
  ring.style.border = '3px solid ' + d.color;
  ring.style.color  = d.color;
  document.getElementById('risk-dp-score-label').textContent = d.label + ' risk · ' + d.factors.length + ' contributing factors';
  document.getElementById('risk-dp-factors').innerHTML = d.factors.map(function(f) {
    const pct = Math.round(f.score * 10);
    return '<div style="background:var(--bg-elevated);border-radius:8px;padding:10px 12px">'
      + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'
      + '<span style="font-size:12px;font-weight:600;color:var(--text-secondary)">' + f.name + '</span>'
      + '<span style="font-family:\'JetBrains Mono\',monospace;font-size:12px;color:' + f.color + ';font-weight:700">' + f.score.toFixed(1) + '</span>'
      + '</div>'
      + '<div style="height:4px;background:var(--bg-card);border-radius:2px;margin-bottom:6px">'
      + '<div style="width:' + pct + '%;height:100%;background:' + f.color + ';border-radius:2px;transition:width .4s ease"></div>'
      + '</div>'
      + '<div style="font-size:11px;color:var(--text-muted);line-height:1.5">' + f.detail + '</div>'
      + '</div>';
  }).join('');
  document.getElementById('risk-detail').style.width = '480px';
  document.getElementById('risk-list').style.flex = '0 0 calc(100% - 480px)';
}

function closeRisk() {
  document.querySelectorAll('.risk-row').forEach(r => r.style.background = '');
  document.getElementById('risk-detail').style.width = '0';
  document.getElementById('risk-list').style.flex = '1';
}

function filterRisk() {
  const q = document.getElementById('riskSearch').value.toLowerCase();
  document.querySelectorAll('#risk-tbody .risk-row').forEach(function(row) {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function exportCSV() {
  const rows = [...document.querySelectorAll('#viol-tbody .viol-row')]
    .filter(function(r){ return r.style.display!=='none'; })
    .map(function(r){ return [...r.querySelectorAll('td')].map(function(td){ return td.textContent.trim(); }).join(','); });
  const csv = 'Policy,Severity,Deployment,Cluster,Namespace,Time\n' + rows.join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  a.download = 'kvisior8-violations.csv';
  a.click();
  toast('success','CSV Exported','violations-' + new Date().toISOString().slice(0,10) + '.csv');
}

function snoozeViolation() {
  showModal('<div class="modal">'
    + '<div class="modal-header"><span class="modal-title">🔕 Snooze Violation</span>'
    + '<button class="modal-close" onclick="closeModal()">✕</button></div>'
    + '<div class="modal-body">'
    + '<div class="form-group"><label class="form-label">Snooze until</label>'
    + '<select class="form-select"><option>1 hour</option><option>4 hours</option><option selected>1 day</option><option>3 days</option><option>1 week</option></select></div>'
    + '<div class="form-group"><label class="form-label">Reason (optional)</label>'
    + '<textarea class="form-textarea" placeholder="Explain why this violation is being snoozed…"></textarea></div>'
    + '</div><div class="modal-footer">'
    + '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-primary" onclick="closeModal();toast(\'info\',\'Violation snoozed\',\'Will re-alert in 1 day\')">Snooze</button>'
    + '</div></div>');
}

function markResolved() {
  const title = document.getElementById('dp-title').textContent;
  showModal('<div class="modal">'
    + '<div class="modal-header"><span class="modal-title">⚡ Mark as Resolved</span>'
    + '<button class="modal-close" onclick="closeModal()">✕</button></div>'
    + '<div class="modal-body">'
    + '<p style="margin-bottom:12px">Are you sure you want to mark <strong style="color:var(--text-primary)">' + title + '</strong> as resolved?</p>'
    + '<div class="form-group"><label class="form-label">Resolution note</label>'
    + '<textarea class="form-textarea" placeholder="Describe how this was remediated…"></textarea></div>'
    + '</div><div class="modal-footer">'
    + '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-primary" onclick="closeModal();closeViolation();toast(\'success\',\'Violation resolved\',\'Marked as remediated and archived\')">Mark Resolved</button>'
    + '</div></div>');
}

function generateReport() {
  showModal('<div class="modal">'
    + '<div class="modal-header"><span class="modal-title">📋 Generate Compliance Report</span>'
    + '<button class="modal-close" onclick="closeModal()">✕</button></div>'
    + '<div class="modal-body">'
    + '<div class="form-group"><label class="form-label">Report format</label>'
    + '<select class="form-select"><option>PDF</option><option>CSV</option><option>JSON</option></select></div>'
    + '<div class="form-group"><label class="form-label">Standards to include</label>'
    + '<div style="display:flex;flex-direction:column;gap:8px;margin-top:4px">'
    + ['CIS Kubernetes','NIST 800-190','PCI DSS','HIPAA'].map(function(s){
        return '<label style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-secondary);cursor:pointer">'
          + '<input type="checkbox" checked style="accent-color:var(--accent)"> ' + s + '</label>';
      }).join('')
    + '</div></div>'
    + '<div class="form-group"><label class="form-label">Cluster scope</label>'
    + '<select class="form-select"><option>All clusters</option><option>prod-cluster</option><option>dev-cluster</option></select></div>'
    + '</div><div class="modal-footer">'
    + '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-primary" onclick="closeModal();toast(\'success\',\'Report generating…\',\'You will be notified when ready\')">Generate</button>'
    + '</div></div>');
}

function exportVuln() {
  showModal('<div class="modal">'
    + '<div class="modal-header"><span class="modal-title">📥 Export Data</span>'
    + '<button class="modal-close" onclick="closeModal()">✕</button></div>'
    + '<div class="modal-body">'
    + '<div class="form-group"><label class="form-label">Format</label>'
    + '<select class="form-select"><option>CSV</option><option>JSON</option><option>SARIF</option></select></div>'
    + '<div class="form-group"><label class="form-label">Scope</label>'
    + '<select class="form-select"><option>Current view</option><option>All CVEs</option><option>Critical only</option></select></div>'
    + '</div><div class="modal-footer">'
    + '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'
    + '<button class="btn btn-primary" onclick="closeModal();toast(\'success\',\'Export started\',\'Download will begin shortly\')">Export</button>'
    + '</div></div>');
}


export const SYSCALL_LIST = [
  'execve','execveat','clone','fork','vfork',
  'open','openat','openat2','creat',
  'unlink','unlinkat','rename','renameat','renameat2',
  'mkdir','mkdirat',
  'connect','bind','accept','accept4','socket',
  'setuid','setgid','setresuid','setresgid','capset',
  'mount','umount','umount2',
  'ptrace','prctl','setns','unshare',
  'io_uring_setup','io_uring_enter','io_uring_register',
];

function _polSyscallToggle(el) {
  document.querySelectorAll('.sc-chip').forEach(c => c.classList.remove('sc-active'));
  el.classList.add('sc-active');
  const trigger = document.getElementById('pol-sc-trigger-label');
  if (trigger) trigger.textContent = el.dataset.name;
  const panel = document.getElementById('pol-sc-dropdown');
  const arrow = document.getElementById('pol-sc-arrow');
  if (panel) panel.style.display = 'none';
  if (arrow) arrow.style.transform = 'rotate(0deg)';
}

function _polSyscallDropdown() {
  const panel = document.getElementById('pol-sc-dropdown');
  const arrow = document.getElementById('pol-sc-arrow');
  const open  = panel.style.display === 'none' || panel.style.display === '';
  panel.style.display = open ? 'flex' : 'none';
  arrow.style.transform = open ? 'rotate(180deg)' : 'rotate(0deg)';
}

export const DEPLOY_CATEGORIES = [
  { id: 'priv', label: 'Privileged / Escalation', items: [
    'Privileged Container',
    'Container with privilege escalation allowed',
    'CAP_SYS_ADMIN capability added',
    'Drop All Capabilities',
  ]},
  { id: 'host', label: 'Host Access', items: [
    'Host Network',
    'Host PID',
    'Host IPC',
    'Mount Container Runtime Socket',
    'Mounting Sensitive Host Directories',
    'Mount propagation enabled',
  ]},
  { id: 'fs', label: 'Filesystem / Secrets', items: [
    'Read-write root filesystem',
    'Secret Mounted as Environment Variable',
    'Environment Variable Contains Secret',
    'Improper Usage of Orchestrator Secrets Volume',
  ]},
  { id: 'net', label: 'Network / Exposure', items: [
    'Deployments with externally exposed endpoints',
    'Deployments should have at least one ingress Network Policy',
    'Restricted host ports',
    'SSH port exposed',
  ]},
  { id: 'gov', label: 'Policy / Governance', items: [
    'Required Annotation: Email',
    'Required Annotation: Owner/Team',
    'Required Label: Owner/Team',
    'Emergency Deployment Annotation',
  ]},
  { id: 'hyg', label: 'Hygiene', items: [
    'Images with no scans',
    '30-Day Scan Age',
    'No CPU request or memory limit specified',
    'Pod Service Account Token Automatically Mounted',
    'Kubernetes Dashboard Deployed',
  ]},
];
