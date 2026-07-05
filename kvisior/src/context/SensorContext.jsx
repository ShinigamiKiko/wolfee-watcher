
import { createContext, useContext, useState, useEffect, useMemo } from 'react';
import { useBridge } from './BridgeContext';

const SensorCtx = createContext(null);
export const useSensor = () => useContext(SensorCtx);

export function SensorProvider({ children }) {
  const { snapshot, connected } = useBridge();
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    if (snapshot) setLastUpdated(new Date());
  }, [snapshot]);

  const sensorOnline = connected && snapshot !== null;

  const nodes               = snapshot?.nodes               || [];
  const pods                = snapshot?.pods                || [];
  const deployments         = snapshot?.deployments         || [];
  const statefulSets        = snapshot?.stateful_sets       || [];
  const daemonSets          = snapshot?.daemon_sets         || [];
  const namespaces          = snapshot?.namespaces          || [];
  const serviceAccounts     = snapshot?.service_accounts    || [];
  const clusterRoles        = snapshot?.cluster_roles       || [];
  const clusterRoleBindings = snapshot?.cluster_role_bindings || [];
  const roles               = snapshot?.roles               || [];
  const roleBindings        = snapshot?.role_bindings       || [];
  const networkPolicies     = snapshot?.network_policies    || [];
  const secrets             = snapshot?.secrets             || [];
  const crds                = snapshot?.crds                || [];
  const mutatingWebhooks    = snapshot?.mutating_webhooks   || [];
  const validatingWebhooks  = snapshot?.validating_webhooks || [];

  const workloads = useMemo(() => [
    ...deployments .map(d => ({ ...d, _kind: 'Deployment'  })),
    ...statefulSets.map(s => ({ ...s, _kind: 'StatefulSet' })),
    ...daemonSets  .map(d => ({ ...d, _kind: 'DaemonSet'   })),
  ], [deployments, statefulSets, daemonSets]);

  const allRoles = useMemo(() => [
    ...clusterRoles.map(r => ({ ...r, _kind: 'ClusterRole' })),
    ...roles       .map(r => ({ ...r, _kind: 'Role'        })),
  ], [clusterRoles, roles]);

  const allBindings = useMemo(() => [
    ...clusterRoleBindings.map(b => ({ ...b, _kind: 'ClusterRoleBinding' })),
    ...roleBindings       .map(b => ({ ...b, _kind: 'RoleBinding'        })),
  ], [clusterRoleBindings, roleBindings]);

  return (
    <SensorCtx.Provider value={{
      snapshot, sensorOnline, lastUpdated,
      nodes, pods, deployments, statefulSets, daemonSets,
      namespaces, serviceAccounts, secrets, crds,
      mutatingWebhooks, validatingWebhooks,
      clusterRoles, clusterRoleBindings, roles, roleBindings,
      networkPolicies,
      workloads, allRoles, allBindings,
    }}>
      {children}
    </SensorCtx.Provider>
  );
}
