import { Icon } from './Icon';

export function EmptyState({ icon, title, sub, action, compact }) {
  return (
    <div className={`empty-state${compact ? ' empty-state--compact' : ''}`}>
      {icon && <Icon name={icon} size={28} />}
      {title && <div className="empty-title">{title}</div>}
      {sub && <div className="empty-sub">{sub}</div>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}
