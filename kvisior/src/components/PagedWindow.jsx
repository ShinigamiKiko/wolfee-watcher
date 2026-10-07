import { DataWindow } from './DataWindow';
import { Pager } from './Pager';
import { usePaged } from '../hooks/usePaged';

export function PagedWindow({ items, storageKey, label, noun = 'rows', resetKey, deps = [], children }) {
  const { pageItems, pager } = usePaged(items, storageKey, [resetKey]);
  return (
    <DataWindow label={label} deps={[resetKey, ...deps]} footer={<Pager {...pager} noun={noun} />}>
      {children(pageItems)}
    </DataWindow>
  );
}
