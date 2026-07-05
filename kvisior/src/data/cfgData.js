const CFG_DATA = {
  cluster: [
    { title:'prod-cluster', sub:'OpenShift 4.14 &middot; 24 nodes &middot; Online',
      sevColor:'var(--accent-3)',
      fields:[['Type','OpenShift Container Platform 4.14'],['Provider','On-premise / VMware'],['API Server','https://api.prod-cluster.acme.io:6443'],['K8s Version','1.27.8'],['OCP Version','4.14.12'],['Created','Nov 14 2023']],
      sections:[
        { title:'Sensor Status', items:[['Collector','Running · v3.74.0'],['Admission Control','Enabled'],['Last Contact','just now'],['Sensor Version','4.4.2']] },
        { title:'Resources', items:[['Nodes','24 (22 worker, 2 master)'],['Namespaces','18'],['Deployments','1,244'],['Pods Running','3,812'],['Secrets','198'],['Network Policies','42']] },
        { title:'Security', items:[['Policy Violations','47 active'],['Critical CVEs','38'],['Privileged Containers','2'],['Root Containers','6']] }
      ]},
    { title:'dev-cluster', sub:'GKE 1.28 &middot; 8 nodes &middot; Online',
      sevColor:'var(--accent-3)',
      fields:[['Type','Google Kubernetes Engine'],['Provider','GCP / us-central1'],['API Server','https://34.72.18.xx:443'],['K8s Version','1.28.3'],['Node Pool','e2-standard-8'],['Created','Feb 2 2024']],
      sections:[
        { title:'Sensor Status', items:[['Collector','Running · v3.74.0'],['Admission Control','Enabled'],['Last Contact','2m ago'],['Sensor Version','4.4.2']] },
        { title:'Resources', items:[['Nodes','8'],['Namespaces','12'],['Deployments','134'],['Pods Running','412'],['Secrets','74'],['Network Policies','8']] },
        { title:'Security', items:[['Policy Violations','7 active'],['Critical CVEs','0'],['Privileged Containers','1'],['Root Containers','2']] }
      ]},
    { title:'staging', sub:'EKS 1.29 &middot; 6 nodes &middot; Warning',
      sevColor:'var(--warning)',
      fields:[['Type','Amazon EKS'],['Provider','AWS / eu-west-1'],['API Server','https://staging.eks.amazonaws.com'],['K8s Version','1.29.1'],['Node Group','t3.xlarge x6'],['Created','Aug 18 2024']],
      sections:[
        { title:'Sensor Status', items:[['Collector','Degraded — disk pressure'],['Admission Control','Enabled'],['Last Contact','8m ago'],['Sensor Version','4.4.1 (outdated)']] },
        { title:'Resources', items:[['Nodes','6'],['Namespaces','7'],['Deployments','42'],['Pods Running','118'],['Secrets','12'],['Network Policies','3']] },
        { title:'Security', items:[['Policy Violations','3 active'],['Critical CVEs','2'],['Privileged Containers','0'],['Root Containers','1']] }
      ]},
  ],
  ns: [
    { title:'production', sub:'prod-cluster &middot; HIGH risk',
      sevColor:'var(--warning)',
      fields:[['Cluster','prod-cluster'],['Status','Active'],['Created','Nov 14 2023'],['Labels','env=production, team=platform']],
      sections:[
        { title:'Resources', items:[['Deployments','42'],['Pods','124'],['Services','38'],['ConfigMaps','61'],['Secrets','88'],['PersistentVolumeClaims','14']] },
        { title:'Security Findings', items:[['Policy Violations','31'],['Privileged Pods','1'],['Root Containers','3'],['No Resource Limits','8'],['Network Policies','6']] }
      ]},
    { title:'kube-system', sub:'prod-cluster &middot; MEDIUM risk',
      sevColor:'#a78bfa',
      fields:[['Cluster','prod-cluster'],['Status','Active'],['Created','Nov 14 2023'],['Labels','kubernetes.io/metadata.name=kube-system']],
      sections:[
        { title:'Resources', items:[['Deployments','18'],['Pods','47'],['Services','12'],['Secrets','24']] },
        { title:'Security Findings', items:[['Policy Violations','4'],['Privileged Pods','2 (system)'],['Network Policies','2']] }
      ]},
    { title:'legacy', sub:'prod-cluster &middot; CRITICAL risk',
      sevColor:'var(--danger)',
      fields:[['Cluster','prod-cluster'],['Status','Active'],['Created','Mar 1 2022'],['Labels','env=legacy, deprecation=pending']],
      sections:[
        { title:'Resources', items:[['Deployments','4'],['Pods','8'],['Secrets','9'],['Network Policies','0 ⚠']] },
        { title:'Security Findings', items:[['Policy Violations','12'],['EOL Base Images','2'],['Root Containers','2'],['No Network Policies','⚠ All traffic unrestricted']] }
      ]},
    { title:'monitoring', sub:'prod-cluster &middot; LOW risk', sevColor:'var(--accent-3)',
      fields:[['Cluster','prod-cluster'],['Status','Active'],['Created','Dec 2023'],['Labels','app=prometheus, team=sre']],
      sections:[{ title:'Resources', items:[['Deployments','11'],['Pods','22'],['Secrets','16'],['Network Policies','3']] },{ title:'Security Findings', items:[['Policy Violations','1'],['No Critical CVEs','&#10003;']] }]},
    { title:'default', sub:'dev-cluster &middot; LOW risk', sevColor:'var(--accent-3)',
      fields:[['Cluster','dev-cluster'],['Status','Active'],['Created','Feb 2024']],
      sections:[{ title:'Resources', items:[['Deployments','7'],['Pods','14'],['Secrets','12']] },{ title:'Security Findings', items:[['Policy Violations','2'],['Privileged Containers','1']] }]},
    { title:'ingress', sub:'prod-cluster &middot; MEDIUM risk', sevColor:'#a78bfa',
      fields:[['Cluster','prod-cluster'],['Status','Active'],['Created','Nov 2023']],
      sections:[{ title:'Resources', items:[['Deployments','2'],['Services','2'],['Network Policies','4']] },{ title:'Security Findings', items:[['Policy Violations','1'],['Internet-Facing','Yes']] }]},
    { title:'ci', sub:'dev-cluster &middot; LOW risk', sevColor:'var(--accent-3)',
      fields:[['Cluster','dev-cluster'],['Status','Active'],['Created','Feb 2024']],
      sections:[{ title:'Resources', items:[['Deployments','3'],['Pods','6'],['Secrets','7']] },{ title:'Security Findings', items:[['Policy Violations','0'],['Status','Clean &#10003;']] }]},
  ],
  node: [
    { title:'node-prod-01', sub:'prod-cluster &middot; worker &middot; Ready',
      sevColor:'var(--accent-3)',
      fields:[['Cluster','prod-cluster'],['OS','RHCOS 4.14 (Red Hat CoreOS)'],['Kernel','5.14.0-362.el9.x86_64'],['Architecture','amd64'],['Container Runtime','cri-o://1.27.3'],['kubelet','v1.27.8']],
      sections:[
        { title:'Capacity', items:[['CPU','48 cores'],['Memory','192 GB'],['Ephemeral Storage','480 GB'],['Pods (used/max)','38 / 110']] },
        { title:'Labels', items:[['node-role','worker'],['topology.zone','us-east-1a'],['kubernetes.io/hostname','node-prod-01']] },
        { title:'Conditions', items:[['Ready','True'],['MemoryPressure','False'],['DiskPressure','False'],['PIDPressure','False']] }
      ]},
    { title:'node-prod-02', sub:'prod-cluster &middot; worker &middot; Ready',
      sevColor:'var(--accent-3)',
      fields:[['Cluster','prod-cluster'],['OS','RHCOS 4.14'],['Kernel','5.14.0-362.el9.x86_64'],['Architecture','amd64'],['Container Runtime','cri-o://1.27.3'],['kubelet','v1.27.8']],
      sections:[
        { title:'Capacity', items:[['CPU','48 cores'],['Memory','192 GB'],['Pods (used/max)','41 / 110']] },
        { title:'Conditions', items:[['Ready','True'],['MemoryPressure','False'],['DiskPressure','False']] }
      ]},
    { title:'node-master-01', sub:'prod-cluster &middot; control-plane &middot; Ready',
      sevColor:'var(--accent-3)',
      fields:[['Cluster','prod-cluster'],['OS','RHCOS 4.14'],['Kernel','5.14.0-362.el9.x86_64'],['Container Runtime','cri-o://1.27.3']],
      sections:[
        { title:'Capacity', items:[['CPU','16 cores'],['Memory','64 GB'],['Pods (used/max)','12 / 250']] },
        { title:'Taints', items:[['node-role/control-plane','NoSchedule']] }
      ]},
    { title:'node-dev-01', sub:'dev-cluster &middot; worker &middot; Ready',
      sevColor:'var(--accent-3)',
      fields:[['Cluster','dev-cluster'],['OS','Ubuntu 22.04 LTS'],['Kernel','5.15.0-89-generic'],['Container Runtime','containerd://1.7.8']],
      sections:[
        { title:'Capacity', items:[['CPU','16 cores'],['Memory','64 GB'],['Pods (used/max)','21 / 110']] },
        { title:'Conditions', items:[['Ready','True'],['MemoryPressure','False'],['DiskPressure','False']] }
      ]},
    { title:'node-stg-01', sub:'staging &middot; worker &middot; MemoryPressure',
      sevColor:'var(--warning)',
      fields:[['Cluster','staging'],['OS','Ubuntu 22.04 LTS'],['Kernel','5.15.0-91-generic'],['Container Runtime','containerd://1.7.6']],
      sections:[
        { title:'Capacity', items:[['CPU','8 cores'],['Memory','32 GB'],['Pods (used/max)','29 / 110 ⚠']] },
        { title:'Conditions', items:[['Ready','True'],['MemoryPressure','<span style="color:var(--warning)">True</span>'],['DiskPressure','<span style="color:var(--warning)">True</span>']] }
      ]},
  ],
  dep: [
    { title:'payments-svc', sub:'production &middot; 3/3 replicas &middot; Running',
      sevColor:'var(--warning)',
      fields:[['Namespace','production'],['Cluster','prod-cluster'],['Image','gcr.io/payments/api:v2.14'],['Service Account','payments-sa'],['Created','3d ago'],['Strategy','RollingUpdate']],
      sections:[
        { title:'Containers', items:[['payments-api','gcr.io/payments/api:v2.14'],['Port','8080/TCP'],['CPU Request/Limit','100m / none ⚠'],['Mem Request/Limit','128Mi / none ⚠'],['Run as Root','No'],['Privileged','No']] },
        { title:'Volumes', items:[['payments-config','ConfigMap → /etc/config'],['payments-tls','Secret → /etc/tls']] },
        { title:'Security Context', items:[['runAsNonRoot','true'],['readOnlyRootFilesystem','false ⚠'],['allowPrivilegeEscalation','false']] }
      ]},
    { title:'auth-gateway', sub:'production &middot; 2/2 replicas &middot; Running',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','production'],['Cluster','prod-cluster'],['Image','quay.io/auth/gateway:latest ⚠'],['Service Account','default'],['Created','7d ago'],['Strategy','RollingUpdate']],
      sections:[
        { title:'Containers', items:[['auth-gw','quay.io/auth/gateway:latest'],['Port','8443/TCP'],['CPU Request/Limit','200m / 500m'],['Mem Request/Limit','256Mi / 512Mi'],['Run as Root','Yes ⚠'],['Privileged','No']] },
        { title:'Volumes', items:[['tls-secret','Secret → /etc/ssl/certs']] },
        { title:'Security Context', items:[['runAsNonRoot','false ⚠'],['readOnlyRootFilesystem','false ⚠']] }
      ]},
    { title:'debug-tools', sub:'default &middot; 1/1 replicas &middot; Warning',
      sevColor:'var(--danger)',
      fields:[['Namespace','default'],['Cluster','dev-cluster'],['Image','docker.io/tools:latest ⚠'],['Service Account','default'],['Created','28d ago']],
      sections:[
        { title:'Containers', items:[['debug','docker.io/tools:latest'],['CPU Request/Limit','none ⚠ / none ⚠'],['Privileged','<span style="color:var(--danger)">Yes ⚠</span>'],['Run as Root','<span style="color:var(--danger)">Yes ⚠</span>']] },
        { title:'Security Context', items:[['privileged','<span style="color:var(--danger)">true</span>'],['runAsUser','0 (root) ⚠'],['hostPID','<span style="color:var(--danger)">true</span>'],['hostNetwork','<span style="color:var(--danger)">true</span>']] }
      ]},
    { title:'nginx-ingress', sub:'ingress &middot; 2/2 replicas &middot; Running',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','ingress'],['Cluster','prod-cluster'],['Image','docker.io/nginx:1.25.3'],['Service Account','nginx-sa'],['Created','21d ago']],
      sections:[
        { title:'Containers', items:[['nginx','docker.io/nginx:1.25.3'],['Ports','80/TCP, 443/TCP'],['CPU Request/Limit','100m / 500m'],['Mem Request/Limit','128Mi / 256Mi']] },
        { title:'Security Context', items:[['runAsNonRoot','true'],['readOnlyRootFilesystem','true'],['allowPrivilegeEscalation','false']] }
      ]},
    { title:'redis-cache', sub:'production &middot; 1/1 replicas &middot; Running',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','production'],['Cluster','prod-cluster'],['Image','docker.io/redis:7.2-alpine'],['Service Account','default'],['Created','8d ago']],
      sections:[
        { title:'Containers', items:[['redis','docker.io/redis:7.2-alpine'],['Port','6379/TCP'],['CPU Request/Limit','100m / 250m'],['Mem Request/Limit','128Mi / 512Mi']] },
        { title:'Volumes', items:[['redis-data','PVC → /data'],['redis-config','ConfigMap → /etc/redis']] }
      ]},
    { title:'legacy-api', sub:'legacy &middot; 3/3 replicas &middot; Running',
      sevColor:'var(--danger)',
      fields:[['Namespace','legacy'],['Cluster','prod-cluster'],['Image','legacy-registry.io/api:v3.1'],['Service Account','default'],['Created','142d ago']],
      sections:[
        { title:'Containers', items:[['api','legacy-registry.io/api:v3.1'],['Port','8080/TCP, 22/TCP ⚠'],['CPU Request/Limit','none ⚠ / none ⚠'],['Privileged','<span style="color:var(--danger)">Yes</span>']] },
        { title:'Security Context', items:[['runAsUser','0 (root) ⚠'],['privileged','<span style="color:var(--danger)">true</span>'],['hostNetwork','<span style="color:var(--danger)">true</span>']] }
      ]},
  ],
  sa: [
    { title:'cluster-admin-sa', sub:'kube-system &middot; prod-cluster &middot; CRITICAL',
      sevColor:'var(--danger)',
      fields:[['Namespace','kube-system'],['Cluster','prod-cluster'],['Created','Nov 2023'],['Auto-mount Token','Yes ⚠'],['Image Pull Secrets','none']],
      sections:[
        { title:'Role Bindings', items:[['cluster-admin (ClusterRoleBinding)','All namespaces — full access ⚠'],['system:kube-controller-manager','kube-system'],['system:node-proxier','kube-system']] },
        { title:'Used By', items:[['kube-controller-manager','kube-system'],['node-problem-detector','kube-system']] }
      ]},
    { title:'payments-sa', sub:'production &middot; prod-cluster &middot; HIGH',
      sevColor:'var(--warning)',
      fields:[['Namespace','production'],['Cluster','prod-cluster'],['Created','Nov 2023'],['Auto-mount Token','Yes ⚠']],
      sections:[
        { title:'Role Bindings', items:[['payments-role (RoleBinding)','production'],['secret-reader (RoleBinding)','production'],['configmap-reader (RoleBinding)','production']] },
        { title:'Used By', items:[['payments-svc','production'],['payments-worker','production']] }
      ]},
    { title:'default', sub:'production &middot; prod-cluster &middot; MEDIUM',
      sevColor:'#a78bfa',
      fields:[['Namespace','production'],['Cluster','prod-cluster'],['Auto-mount Token','No']],
      sections:[
        { title:'Role Bindings', items:[['view (RoleBinding)','production'],['pod-reader (RoleBinding)','production']] },
        { title:'Used By', items:[['auth-gateway','production']] }
      ]},
    { title:'ci-runner', sub:'default &middot; dev-cluster &middot; LOW',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','default'],['Cluster','dev-cluster'],['Auto-mount Token','No']],
      sections:[
        { title:'Role Bindings', items:[['ci-deploy-role (RoleBinding)','default']] },
        { title:'Used By', items:[['ci-pipeline','default']] }
      ]},
    { title:'monitoring-sa', sub:'monitoring &middot; prod-cluster &middot; LOW',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','monitoring'],['Cluster','prod-cluster'],['Auto-mount Token','No']],
      sections:[
        { title:'Role Bindings', items:[['prometheus-role (RoleBinding)','monitoring'],['node-metrics-reader (ClusterRoleBinding)','cluster-wide']] },
        { title:'Used By', items:[['prometheus','monitoring'],['grafana','monitoring']] }
      ]},
  ],
  role: [
    { title:'cluster-admin', sub:'ClusterRole &middot; prod-cluster &middot; 3 bindings',
      sevColor:'var(--danger)',
      fields:[['Type','ClusterRole'],['Cluster','prod-cluster'],['Created','Nov 2023']],
      sections:[
        { title:'Rules', items:[['apiGroups','* (all)'],['resources','* (all)'],['verbs','* (all) — full cluster access ⚠']] },
        { title:'Bindings', items:[['cluster-admin-sa (ClusterRoleBinding)','All namespaces'],['admin-user (ClusterRoleBinding)','All namespaces'],['system:masters (ClusterRoleBinding)','All namespaces']] }
      ]},
    { title:'edit', sub:'ClusterRole &middot; prod-cluster &middot; 5 bindings',
      sevColor:'#a78bfa',
      fields:[['Type','ClusterRole'],['Cluster','prod-cluster'],['Created','Nov 2023']],
      sections:[
        { title:'Rules', items:[['Pods','get, list, watch, create, update, patch, delete'],['Deployments','get, list, watch, create, update, patch, delete'],['Services','get, list, watch, create, update, patch'],['ConfigMaps','get, list, watch, create, update, patch, delete'],['Secrets','get, list, watch']] },
        { title:'Bindings (5)', items:[['payments-team','production'],['auth-team','production'],['infra-team','kube-system'],['dev-leads','default'],['platform-eng','monitoring']] }
      ]},
    { title:'view', sub:'ClusterRole &middot; prod-cluster &middot; 14 bindings',
      sevColor:'var(--accent-3)',
      fields:[['Type','ClusterRole'],['Cluster','prod-cluster']],
      sections:[
        { title:'Rules', items:[['Pods','get, list, watch'],['Deployments','get, list, watch'],['Services','get, list, watch'],['ConfigMaps','get, list, watch'],['Secrets','list only']] },
        { title:'Bindings', items:[['14 subjects bound (teams, SAs)','Various namespaces']] }
      ]},
    { title:'payments-role', sub:'Role &middot; production &middot; 2 bindings',
      sevColor:'var(--accent-3)',
      fields:[['Type','Role'],['Namespace','production'],['Cluster','prod-cluster'],['Created','Nov 2023']],
      sections:[
        { title:'Rules', items:[['Secrets','get, list (payments-db-creds, api-keys)'],['ConfigMaps','get, list'],['Pods','get, list, watch'],['Endpoints','get, list']] },
        { title:'Bindings', items:[['payments-sa (RoleBinding)','production'],['payments-worker-sa (RoleBinding)','production']] }
      ]},
    { title:'ci-deploy-role', sub:'Role &middot; default &middot; 1 binding',
      sevColor:'var(--accent-3)',
      fields:[['Type','Role'],['Namespace','default'],['Cluster','dev-cluster']],
      sections:[
        { title:'Rules', items:[['Deployments','get, list, update, patch'],['Pods','get, list, watch'],['Secrets','get (ci-registry-creds only)']] },
        { title:'Bindings', items:[['ci-runner (RoleBinding)','default']] }
      ]},
  ],
  secret: [
    { title:'api-keys', sub:'production &middot; Opaque &middot; CRITICAL',
      sevColor:'var(--danger)',
      fields:[['Namespace','production'],['Type','Opaque'],['Created','84d ago'],['Last Updated','12d ago'],['Data Keys','STRIPE_SECRET_KEY, INTERNAL_API_KEY, WEBHOOK_SECRET']],
      sections:[
        { title:'Security Issues', items:[['Exposed in env vars','auth-gateway ⚠'],['Plain-text mount','Yes — /etc/secrets ⚠'],['Rotation','Never rotated ⚠']] },
        { title:'Used By', items:[['auth-gateway','production (env var mount)']] }
      ]},
    { title:'payments-db-creds', sub:'production &middot; Opaque &middot; HIGH',
      sevColor:'var(--warning)',
      fields:[['Namespace','production'],['Type','Opaque'],['Created','142d ago'],['Data Keys','DB_HOST, DB_USER, DB_PASSWORD, DB_NAME']],
      sections:[
        { title:'Security Issues', items:[['Age','142d — rotation recommended ⚠'],['Volume Mount','/etc/db-creds (file mount)'],['Rotation','Last rotated 142d ago']] },
        { title:'Used By', items:[['payments-svc','production'],['payments-worker','production']] }
      ]},
    { title:'docker-registry', sub:'default &middot; dockerconfigjson &middot; MEDIUM',
      sevColor:'#a78bfa',
      fields:[['Namespace','default'],['Type','kubernetes.io/dockerconfigjson'],['Created','201d ago'],['Registries','docker.io, legacy-registry.io']],
      sections:[
        { title:'Security Issues', items:[['Unused','No workload references ⚠'],['Age','201d — verify still needed']] },
        { title:'Used By', items:[['No active deployments','—']] }
      ]},
    { title:'tls-cert-prod', sub:'production &middot; kubernetes.io/tls &middot; LOW',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','production'],['Type','kubernetes.io/tls'],['Created','32d ago'],['Expires','In 333d (Mar 2026)'],['CN','*.acme.io']],
      sections:[
        { title:'Certificate', items:[['Issuer','Let\'s Encrypt R3'],['Subject','*.acme.io'],['Key Type','RSA 2048'],['Expiry','Mar 7 2026']] },
        { title:'Used By', items:[['nginx-ingress','ingress namespace']] }
      ]},
    { title:'redis-password', sub:'production &middot; Opaque &middot; MEDIUM',
      sevColor:'#a78bfa',
      fields:[['Namespace','production'],['Type','Opaque'],['Created','142d ago'],['Data Keys','REDIS_PASSWORD']],
      sections:[
        { title:'Security Issues', items:[['Age','142d — rotation recommended'],['Multiple users','Used by 2 workloads']] },
        { title:'Used By', items:[['redis-cache','production'],['payments-svc','production']] }
      ]},
    { title:'ci-registry-creds', sub:'default &middot; dockerconfigjson &middot; LOW',
      sevColor:'var(--accent-3)',
      fields:[['Namespace','default'],['Type','kubernetes.io/dockerconfigjson'],['Created','310d ago'],['Registries','gcr.io, quay.io']],
      sections:[
        { title:'Security Issues', items:[['Age','310d — verify still needed'],['Status','Active — used by ci-runner']] },
        { title:'Used By', items:[['ci-runner (ServiceAccount)','default']] }
      ]},
  ]
};

function openCfg(type, idx) {
};
