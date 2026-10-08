import { apiFetch } from '../../data/cluster';
import { useCallback, useEffect, useRef, useState } from 'react';
import { usePerms, actingHeaders } from '../../context/PermissionsContext';
import { Field, Switch, SectionLabel, CodeBlock, EmptyRow } from '../../components/kit';

const REFRESH_MS = 15000;
const STALE_MS = 30000;
const TEST_POLL_MS = 1000;
const TEST_TIMEOUT_MS = 20000;
const DEFAULT_PATH = '/var/log/kubernetes/audit.log';

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

const READER = {
  reading: ['Reading', 't-ok'],
  starting: ['Starting', 't-muted'],
  'no-file': ['File not found', 't-danger'],
  'delivery-failing': ['Cannot reach kvisior', 't-warning'],
};

function span(s) {
  if (s < 90) return `${s} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 129600) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

function ago(iso) {
  if (!iso) return '';
  return `${span(Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000)))} ago`;
}

function size(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

function backlogState(node) {
  if (!node.backlogBytes) return ['Up to date', 't-muted', ''];
  const files = node.backlogFiles === 1 ? '1 file' : `${node.backlogFiles} files`;
  const lag = node.lagSeconds > 0 ? `, ${span(node.lagSeconds)} behind` : '';
  const atRisk = node.headroom != null && node.headroom <= 1;
  return [
    `${size(node.backlogBytes)} in ${files}${lag}`,
    atRisk ? 't-danger' : 't-warning',
    atRisk ? 'The reader is on the oldest kept rotated file: the next rotation can delete records that were not read yet. Raise --audit-log-maxbackup or fix delivery.' : '',
  ];
}

function queueState(q) {
  const used = q.capacity > 0 ? (q.bytes + (q.deadBytes || 0)) / q.capacity : 0;
  const stale = !q.updatedAt || Date.now() - new Date(q.updatedAt).getTime() > 60000;
  if (stale) return ['Not reporting', 't-warning', used];
  if (used >= 0.95) return ['Almost full', 't-danger', used];
  if (used >= 0.8) return ['Filling up', 't-warning', used];
  if (q.pending > 0 && q.lastError) return ['Receiver unreachable', 't-warning', used];
  return ['Delivering', 't-ok', used];
}

function readerState(node, wanted) {
  const fresh = node.tailSeenAt && Date.now() - new Date(node.tailSeenAt).getTime() < STALE_MS;
  if (!fresh) return wanted ? ['Not running', 't-warning'] : ['Off', 't-muted'];
  return READER[node.tailState] || [node.tailState || 'Unknown', 't-muted'];
}

function apiServerState(node) {
  if (!node.apiServer) return ['API server pod not visible', 't-muted'];
  if (!node.auditEnabled) return ['Audit log is off', 't-warning'];
  if (!node.detectedPath) return ['On, file is not on the node', 't-warning'];
  return ['On', 't-ok'];
}

async function request(method, body, path = '') {
  const res = await apiFetch(`/api/audit/log-source${path}`, {
    method,
    headers: actingHeaders(body ? { 'Content-Type': 'application/json' } : {}),
    credentials: 'same-origin',
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export function AuditLogSourceCard({ toast }) {
  const { isAdmin } = usePerms();
  const [view, setView] = useState(null);
  const [error, setError] = useState('');
  const [form, setForm] = useState(null);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState('');
  const [proxies, setProxies] = useState(null);
  const [headersSanitized, setHeadersSanitized] = useState(null);
  const [savingProxies, setSavingProxies] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const adopt = useCallback(data => {
    setView(data);
    setError('');
    setForm(prev => prev || { enabled: !!data.settings?.enabled, path: data.settings?.path || '' });
    setProxies(prev => (prev === null ? data.trustedProxies || '' : prev));
    setHeadersSanitized(prev => (prev === null ? !!data.forwardedHeadersSanitized : prev));
  }, []);

  const saveProxies = async () => {
    setSavingProxies(true);
    try {
      const data = await request('PUT', { proxies, forwardedHeadersSanitized: !!headersSanitized }, '/proxies');
      setView(data);
      setProxies(data.trustedProxies || '');
      setHeadersSanitized(!!data.forwardedHeadersSanitized);
      toast('success', 'Trusted proxies saved', data.trustedProxies && data.forwardedHeadersSanitized
        ? 'New events use the address behind these proxies within a minute'
        : 'New events use the address the API server saw the connection from');
    } catch (e) {
      toast('error', 'Trusted proxies were not saved', String(e.message || e));
    } finally {
      setSavingProxies(false);
    }
  };

  const test = async node => {
    setTesting(node);
    try {
      const { probeId } = await request('POST', { node }, '/test');
      const deadline = Date.now() + TEST_TIMEOUT_MS;
      let answer = null;
      while (!answer && Date.now() < deadline && mounted.current) {
        await wait(TEST_POLL_MS);
        const data = await request('GET');
        if (!mounted.current) return;
        setView(data);
        answer = (data.nodes || []).find(n => n.node === node && n.probeDone === probeId) || null;
      }
      if (!mounted.current) return;
      if (!answer) toast('error', `${node}: no connection`, 'The reader did not answer within 20 seconds');
      else if (answer.probeOk) toast('success', `${node}: connected`, answer.probeDetail);
      else toast('error', `${node}: no connection`, answer.probeDetail);
    } catch (e) {
      if (mounted.current) toast('error', `${node}: no connection`, String(e.message || e));
    } finally {
      if (mounted.current) setTesting('');
    }
  };

  useEffect(() => {
    let alive = true;
    const load = () => request('GET').then(d => alive && adopt(d)).catch(e => alive && setError(String(e.message || e)));
    load();
    const t = setInterval(load, REFRESH_MS);
    return () => { alive = false; clearInterval(t); };
  }, [adopt]);

  const save = async () => {
    setBusy(true);
    try {
      const data = await request('PUT', { enabled: form.enabled, path: form.path.trim(), nodePaths: {} });
      setView(data);
      setForm({ enabled: !!data.settings.enabled, path: data.settings.path || '' });
      toast('success', 'Audit log source saved', form.enabled ? 'The reader starts within a minute' : 'The reader is stopped');
    } catch (e) {
      toast('error', 'Audit log source was not saved', String(e.message || e));
    } finally {
      setBusy(false);
    }
  };

  if (!view || !form) {
    return (
      <div className={`pane empty-state empty-state--compact settings-section ${error ? 't-danger' : ''}`}>
        {error ? `Failed to load the audit log source: ${error}` : 'Loading the audit log source…'}
      </div>
    );
  }

  const { settings, plan, managed } = view;
  const nodes = view.nodes || [];
  const queues = view.queues || [];
  const applied = managed && settings.appliedRev === plan.rev && !settings.applyError;
  const detected = [...new Set(nodes.map(n => n.detectedPath).filter(Boolean))];
  const missing = nodes.filter(n => n.apiServer && !n.auditEnabled);
  const effective = node => form.path.trim() || node.detectedPath || '';
  const statusText = !managed ? 'Follows the chart values until you save here'
    : settings.applyError ? `Could not update the reader: ${settings.applyError}`
    : applied ? `Applied ${ago(settings.appliedAt)}`
    : 'Applying, takes up to a minute';
  const statusTone = settings.applyError ? 't-danger' : applied ? 't-ok' : 't-muted';
  const proxiesUnchanged = proxies === (view.trustedProxies || '') && !!headersSanitized === !!view.forwardedHeadersSanitized;

  return (
    <section className="pane settings-section">
      <div className="pane-head">
        <div className="grow">
          <div className="pane-title">Kubernetes audit log</div>
          <div className="pane-sub">
            Reads the kube-apiserver audit log file on every control-plane node. It adds source IP, client and response code to audit events and makes read actions visible. Each API server writes its own file, so every node is read separately.
          </div>
        </div>
        <span className={`row t-sm ${form.enabled ? 't-ok' : 't-muted'}`}>
          <Switch checked={form.enabled} disabled={!isAdmin} label="Read the audit log" onChange={v => setForm(f => ({ ...f, enabled: v }))} />
          {form.enabled ? 'Reading enabled' : 'Reading disabled'}
        </span>
      </div>
      <div className="pane-body">
        <Field label="Log file path on the node" htmlFor="audit-log-path" className="measure"
          hint={detected.length
            ? 'Leave empty to use the path found in each API server\'s --audit-log-path flag.'
            : 'No path was found automatically. Enter the value of --audit-log-path as it is on the node.'}>
          <input id="audit-log-path" className="input input--block input--mono" value={form.path} disabled={!isAdmin}
            placeholder={detected[0] || DEFAULT_PATH} onChange={e => setForm(f => ({ ...f, path: e.target.value }))} />
        </Field>

        <div className="table-wrap mb-12">
          <table className="data-table data-table--static">
            <thead>
              <tr><th>Control-plane node</th><th>API server audit</th><th>Path in use</th><th>Reader</th><th>Last record</th><th>Backlog</th><th>Connection</th></tr>
            </thead>
            <tbody>
              {nodes.length === 0 && (
                <EmptyRow cols={7}>
                  No control-plane nodes reported yet. sentry-audit reports them within a minute of starting; on managed control planes (EKS, GKE, AKS) there are none.
                </EmptyRow>
              )}
              {nodes.map(node => {
                const [apiText, apiTone] = apiServerState(node);
                const [tailText, tailTone] = readerState(node, managed && settings.enabled);
                const [backlogText, backlogTone, backlogHint] = backlogState(node);
                const path = effective(node);
                return (
                  <tr key={node.node}>
                    <td className="mono t-sm">{node.node}</td>
                    <td className={`t-sm ${apiTone}`}>{apiText}</td>
                    <td className="mono t-sm">
                      {path || <span className="t-muted">not set</span>}
                      {path && path === node.detectedPath && !form.path.trim() && <span className="t-muted"> (found)</span>}
                    </td>
                    <td className={`t-sm ${tailTone}`} title={node.tailError || ''}>{tailText}</td>
                    <td className="t-sm">{node.lastRecordAt ? ago(node.lastRecordAt) : <span className="t-muted">none</span>}</td>
                    <td className={`t-sm ${backlogTone}`} title={backlogHint}>{backlogText}</td>
                    <td>
                      <button type="button" className="btn btn-ghost btn-sm" disabled={!isAdmin || !!testing} onClick={() => test(node.node)}>
                        {testing === node.node ? 'Testing…' : 'Test connection'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {queues.length > 0 && (
          <div className="mb-12">
            <SectionLabel>Admission delivery queue</SectionLabel>
            <div className="table-wrap">
              <table className="data-table data-table--static">
                <thead><tr><th>sentry-audit pod</th><th>State</th><th>Queue</th><th>Lost since start</th><th>Updated</th></tr></thead>
                <tbody>
                  {queues.map(q => {
                    const [text, tone, used] = queueState(q);
                    const lost = (q.rejected || 0) + (q.shed || 0) + (q.quarantined || 0);
                    const actors = Object.entries(q.shedActors || {}).sort((a, b) => b[1] - a[1]).map(([actor, n]) => `${actor}: ${n}`).join('\n');
                    return (
                      <tr key={q.pod}>
                        <td className="mono t-sm">{q.pod}</td>
                        <td className={`t-sm ${tone}`} title={q.lastError || ''}>{text}</td>
                        <td className="t-sm">{`${Math.round(used * 100)}% · ${size(q.bytes + (q.deadBytes || 0))} of ${size(q.capacity)} · ${q.pending} files`}</td>
                        <td className={`t-sm ${lost ? 't-danger' : 't-muted'}`} title={actors ? `Shed while the queue was nearly full:\n${actors}` : ''}>
                          {lost ? `${q.rejected || 0} rejected · ${q.shed || 0} shed · ${q.quarantined || 0} quarantined` : 'none'}
                        </td>
                        <td className="t-sm">{ago(q.updatedAt)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {missing.length > 0 && (
          <details className="disclosure mb-12">
            <summary className="t-warning">The audit log is off on {missing.map(n => n.node).join(', ')}. How to turn it on</summary>
            <div className="t-sm t-secondary mt-8">
              Add these flags to <code className="inline">/etc/kubernetes/manifests/kube-apiserver.yaml</code> on the node and mount the policy file and the log directory into the pod. <code className="inline">Metadata</code> level is enough.
            </div>
            <CodeBlock className="mt-8">{`--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-path=${form.path.trim() || DEFAULT_PATH}
--audit-log-maxsize=100
--audit-log-maxbackup=10`}</CodeBlock>
          </details>
        )}

        <div className="row row--loose">
          {isAdmin && <button type="button" className="btn btn-primary" disabled={busy} onClick={save}>{busy ? 'Saving…' : 'Save'}</button>}
          <span className={`t-sm ${statusTone}`}>{statusText}</span>
        </div>

        <div className="divider" />
        <div className="measure">
          <Field label="Trusted proxies in front of the API server" htmlFor="audit-trusted-proxies"
            hint="By default, source IP rules use the address of the connection to the API server. To use a client address behind a proxy, list its addresses or networks here, separated by commas. Enable forwarded addresses only after verifying that the proxy removes or overwrites client-supplied X-Real-IP and builds X-Forwarded-For from the actual connection. Adding X-Forwarded-For alone is insufficient.">
            <input id="audit-trusted-proxies" className="input input--block input--mono" value={proxies ?? ''} disabled={!isAdmin}
              placeholder="none: use the address the API server saw" onChange={e => setProxies(e.target.value)} />
          </Field>
          <label className="check check--top t-sm mb-12">
            <input type="checkbox" checked={!!headersSanitized} disabled={!isAdmin} onChange={e => setHeadersSanitized(e.target.checked)} />
            Use forwarded client addresses: the proxy sanitizes both X-Forwarded-For and X-Real-IP
          </label>
          {isAdmin && (
            <button type="button" className="btn btn-ghost btn-sm" disabled={savingProxies || proxiesUnchanged} onClick={saveProxies}>
              {savingProxies ? 'Saving…' : 'Save trusted proxies'}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
