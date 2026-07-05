import { Component } from 'react';
import { STATUS_COLOR, SEV, sev, SEV_ORDER, fmt } from './auditConsts';

class AuditBoundary extends Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  render() {
    if (this.state.err) return (
      <div style={{padding:24,color:'var(--danger)',fontFamily:'monospace',fontSize:12}}>
        <b>Error:</b><pre>{String(this.state.err)}</pre>
      </div>
    );
    return this.props.children;
  }
}

export { AuditBoundary, STATUS_COLOR, SEV, sev, SEV_ORDER, fmt };
