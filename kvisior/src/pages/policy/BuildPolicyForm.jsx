import { useState } from 'react';

export function BuildPolicyForm({ name, sev, onSave, onClose, initial }) {
  const [instruction,        setInstruction]        = useState(initial?.buildInstruction || '');
  const [trustedRegistries,  setTrustedRegistries]  = useState(initial?.trustedRegistries || '');
  const [ns,                 setNs]                 = useState(initial?.namespace || '');
  const [alertOnly,          setAlertOnly]          = useState(initial?.alertOnly ?? false);

  const canSave = (name || instruction || trustedRegistries).trim() &&
                  (instruction.trim() || trustedRegistries.trim());

  const handleCreate = () => {
    if (!canSave) return;
    onSave({
      id:               initial?.id || `build-${Date.now()}`,
      name:             (name || instruction || trustedRegistries).trim(),
      sev:              sev.toUpperCase(),
      detType:          'Build',
      buildInstruction: instruction.trim(),
      trustedRegistries: trustedRegistries.trim(),
      namespace:        ns.trim(),
      alertOnly,
      enabled:          initial?.enabled !== false,
      syscall:          '*',
      category:         '*',
    });
    onClose();
  };

  return (
    <div>
      <div className="cpol-field">
        <label className="cpol-label">
          Vulnerable Instruction
          <span className="cpol-label-note">
            — pattern to detect in image layers
          </span>
        </label>
        <input className="cpol-input cpol-input--mono" value={instruction} onChange={e => setInstruction(e.target.value)}
          placeholder="e.g. :latest  or  debug  or  ubuntu:18"
          autoFocus />
        <div className="cpol-hint">
           Text matching is case-insensitive. Examples: <code>curl</code> · <code>apt-get install</code> · <code>USER root</code>
        </div>
      </div>

      <div className="cpol-field">
        <label className="cpol-label">
          Trusted Registries
          <span className="cpol-label-note">
            — alert if image is NOT from these registries
          </span>
        </label>
        <input className="cpol-input cpol-input--mono" value={trustedRegistries} onChange={e => setTrustedRegistries(e.target.value)}
          placeholder="e.g. harbor.company.ru, gcr.io/my-project (comma-separated)" />
        <div className="cpol-hint">
          Images not matching any of these prefixes will trigger an alert. Leave empty to skip registry check.
        </div>
      </div>

      <div className="cpol-field">
        <label className="cpol-label">Namespace Filter</label>
        <input className="cpol-input" value={ns} onChange={e => setNs(e.target.value)}
          placeholder="e.g. production (empty = all)" />
      </div>

      <div className="cpol-field">
        <label className="check">
          <input type="checkbox" checked={alertOnly} onChange={e => setAlertOnly(e.target.checked)} />
          <span>Alert</span>
        </label>
      </div>

      <div className="cpol-actions">
        <button className="cpol-btn" onClick={onClose}>Cancel</button>
        <button className="cpol-btn primary" onClick={handleCreate} disabled={!canSave}>
          {initial ? 'Save changes' : 'Create & Enable'}
        </button>
      </div>
    </div>
  );
}
