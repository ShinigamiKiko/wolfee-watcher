import { Component } from 'react';
import { useLocation } from 'react-router-dom';
import { Icon } from './Icon';

class Boundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('page failed to render', error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="page-error" role="alert">
        <Icon name="alert" size={28} />
        <div className="page-error__title">This page failed to load</div>
        <div className="page-error__sub">{String(this.state.error?.message || this.state.error)}</div>
        <button className="btn btn-primary" onClick={() => window.location.reload()}>
          <Icon name="refresh" /> Reload
        </button>
      </div>
    );
  }
}

export function RouteErrorBoundary({ children }) {
  const { pathname } = useLocation();
  return <Boundary key={pathname}>{children}</Boundary>;
}
