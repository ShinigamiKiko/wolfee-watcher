import { SelectMenu } from '../../components/kit';

export function NsDropdown({ nsFilter, setNsFilter, namespaces }) {
  return (
    <SelectMenu size="sm" label="Namespace" value={nsFilter} onChange={setNsFilter}
      options={[{ value: 'all', label: 'All namespaces' }, ...namespaces.map(ns => ({ value: ns, label: ns }))]} />
  );
}
