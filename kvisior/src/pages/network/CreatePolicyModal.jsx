import { useState } from 'react';
import { toYaml, buildFormYaml } from './networkPolicyUtils';

export function CreatePolicyModal({ namespaces, onClose, onApplied }) {

  const [copied, setCopied] = useState(false);
  const [form, setForm] = useState({
    name:'', namespace:namespaces[0]||'default', podSelector:'',
    typeIngress:true, typeEgress:true,
    ingressPeers:'', ingressPorts:'', egressPeers:'', egressPorts:'',
  });

  const set  = (k,v) => setForm(f=>({...f,[k]:v}));
  const yaml = buildFormYaml(form, toYaml);
  const valid = form.name.trim()&&form.namespace.trim()&&form.podSelector.trim()&&(form.typeIngress||form.typeEgress);

  const copyYaml = () => navigator.clipboard.writeText(yaml).then(()=>{setCopied(true);setTimeout(()=>setCopied(false),2000);});



  const title = 'Create NetworkPolicy';

  return (
    <div className="np-modal-overlay" onClick={onClose}>
      <div className="np-modal" onClick={e=>e.stopPropagation()}>
        <div className="np-modal-header">
          <span className="np-modal-title">{title}</span>
          <button className="net-sb-close" onClick={onClose}>✕</button>
        </div>

        {(
          <div className="np-modal-body">
            <div className="np-modal-cols">
              <div className="np-modal-form">
                <div className="np-field-group">
                  <label>Policy name</label>
                  <input className="np-input" placeholder="my-policy" value={form.name} onChange={e=>set('name',e.target.value)}/>
                </div>
                <div className="np-field-group">
                  <label>Namespace</label>
                  <select className="np-input" value={form.namespace} onChange={e=>set('namespace',e.target.value)}>
                    {namespaces.map(ns=><option key={ns}>{ns}</option>)}
                    <option value="default">default</option>
                  </select>
                </div>
                <div className="np-field-group">
                  <label>Pod selector <span className="np-field-hint">(app=…)</span></label>
                  <input className="np-input" placeholder="sensor" value={form.podSelector} onChange={e=>set('podSelector',e.target.value)}/>
                </div>
                <div className="np-field-group">
                  <label>Policy types</label>
                  <div className="np-checkrow">
                    <label className="np-check"><input type="checkbox" checked={form.typeIngress} onChange={e=>set('typeIngress',e.target.checked)}/> Ingress</label>
                    <label className="np-check"><input type="checkbox" checked={form.typeEgress}  onChange={e=>set('typeEgress', e.target.checked)}/> Egress</label>
                  </div>
                </div>
                {form.typeIngress&&<>
                  <div className="np-field-sep">Ingress</div>
                  <div className="np-field-group">
                    <label>Allow from <span className="np-field-hint">(app labels, comma-separated)</span></label>
                    <input className="np-input" placeholder="kvisior8-ui, prometheus" value={form.ingressPeers} onChange={e=>set('ingressPeers',e.target.value)}/>
                    {!form.ingressPeers.trim()&&<span className="np-field-warn">empty = deny all ingress</span>}
                  </div>
                  <div className="np-field-group">
                    <label>Ports <span className="np-field-hint">(e.g. 8080, TCP/443)</span></label>
                    <input className="np-input" placeholder="8080" value={form.ingressPorts} onChange={e=>set('ingressPorts',e.target.value)}/>
                  </div>
                </>}
                {form.typeEgress&&<>
                  <div className="np-field-sep">Egress</div>
                  <div className="np-field-group">
                    <label>Allow to <span className="np-field-hint">(app labels, comma-separated)</span></label>
                    <input className="np-input" placeholder="redis, postgres" value={form.egressPeers} onChange={e=>set('egressPeers',e.target.value)}/>
                    {!form.egressPeers.trim()&&<span className="np-field-warn">empty = deny all egress</span>}
                  </div>
                  <div className="np-field-group">
                    <label>Ports <span className="np-field-hint">(e.g. 6379, TCP/5432)</span></label>
                    <input className="np-input" placeholder="6379" value={form.egressPorts} onChange={e=>set('egressPorts',e.target.value)}/>
                  </div>
                </>}
              </div>
              <div className="np-modal-yaml-wrap">
                <div className="np-modal-yaml-hdr">
                  <span>YAML preview</span>
                  <button className="np-copy-btn" onClick={copyYaml}>{copied?'✓ Copied':'Copy'}</button>
                </div>
                <pre className="np-modal-yaml">{yaml}</pre>
              </div>
            </div>
          </div>
        )}



        <div className="np-modal-footer">
          <button className="np-modal-btn np-modal-btn--ghost" onClick={onClose}>Cancel</button>
          <button className="np-modal-btn np-modal-btn--secondary" onClick={copyYaml}>{copied?'✓ Copied':'Copy YAML'}</button>
        </div>
      </div>
    </div>
  );
}
