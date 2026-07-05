import { appDeps, appPods, wlContainers, SYS_NS } from './checksCIS';
import { allPods, allNamespaces, allDaemonSets, readyNodes, findByName, parseSemver, cmpSemver } from './checksFSTEC_helpers';

const INTEGRITY = [
  { id:'fstec-12.1', fstecRef:'12.1', class:'6/5/4',
    cat:'Целостность', title:'12.1 — Образы запускаются по digest (sha256), а не по тегам',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => wlContainers(dep).some(c => {
        const img = c.image || '';
        return !img.includes('@sha256:') && (img.endsWith(':latest') || !img.includes(':'));
      }));
      return { passing: deps.length - bad.length, total: Math.max(deps.length,1),
        entities: bad.map(d=>`${d.metadata?.namespace}/${d.metadata?.name}`).filter(Boolean),
        fix: 'п.12.1: контроль целостности образов. Используйте ссылки по digest (image@sha256:…) либо фиксированные semver-теги вместо :latest.' };
    }},
  { id:'fstec-12.2', fstecRef:'12.1', class:'6/5/4',
    cat:'Целостность', title:'12.1 — imagePullPolicy установлена (не Always без digest)',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => wlContainers(dep).some(c => {
        const img = c.image || '';
        const policy = c.imagePullPolicy || 'IfNotPresent';
        return policy === 'Always' && !img.includes('@sha256:');
      }));
      return { passing: deps.length - bad.length, total: Math.max(deps.length,1),
        entities: bad.map(d=>`${d.metadata?.namespace}/${d.metadata?.name}`).filter(Boolean),
        fix: 'Комбинация imagePullPolicy:Always + тег без digest создаёт риск подмены образа. Либо используйте digest, либо IfNotPresent.' };
    }},
];

const AUDIT = [
  { id:'fstec-13.1', fstecRef:'13.1', class:'6/5/4',
    cat:'Аудит', title:'13.1 — Ведётся журнал событий безопасности',
    fn(d) {
      const allWl = [
        ...(d.snap?.deployments || []),
        ...(d.snap?.daemon_sets || []),
        ...(d.snap?.stateful_sets || []),
      ];
      const REQUIRED = [
        { name:'sentry-audit',     hint:'admission-события API'   },
        { name:'tracee-bridge',    hint:'syscall-события'         },
        { name:'anomaly-detector', hint:'поведенческие события'   },
      ];
      const missing = REQUIRED.filter(c => !allWl.some(w =>
        (w.metadata?.name || '').toLowerCase().includes(c.name)));
      return { passing: REQUIRED.length - missing.length, total: REQUIRED.length,
        entities: missing.map(c => `${c.name} (${c.hint}) — компонент журнала не развёрнут`),
        fix: 'п.13.1: разверните полный пайплайн журналирования — sentry-audit (admission), tracee-bridge (syscalls), anomaly-detector (поведение).' };
    }},
  { id:'fstec-13.3', fstecRef:'13.2', class:'5/4',
    cat:'Аудит', title:'13.2 — События уязвимостей и нарушений конфигурации регистрируются',
    fn(d) {
      const vulnFindings  = (d.scan?.results || []).some(r => (r.summary?.critical||0) + (r.summary?.high||0) > 0);
      const configFindings = (d.snap?.violations?.length || 0) > 0
                          || (d.compliance?.findings?.length || 0) > 0;
      const passing = (vulnFindings || configFindings) ? 1 : 0;
      return { passing, total: 1,
        entities: passing ? [] : ['Нет записанных findings по уязвимостям/конфигурации'],
        fix: 'Для 5 и 4 классов (п.13.2) обязательна регистрация событий выявления уязвимостей и некорректной конфигурации.' };
    }},
  { id:'fstec-13.4', fstecRef:'13.1 (kube-apiserver audit)', class:'6/5/4',
    cat:'Аудит', title:'13.1 — kube-apiserver запущен с --audit-log-path и --audit-policy-file',
    fn(d) {
      const apiservers = allPods(d).filter(p =>
        p.metadata?.namespace === 'kube-system' &&
        (p.metadata?.name || '').startsWith('kube-apiserver'));
      if (apiservers.length === 0) {
        return { passing: 1, total: 1, entities: [],
          fix: 'kube-apiserver не виден в kube-system (managed control-plane). Проверьте конфигурацию аудита у провайдера.' };
      }
      const total = apiservers.length;
      const bad = apiservers.filter(p => {
        const args = (p.spec?.containers || []).flatMap(c => [...(c.command||[]), ...(c.args||[])]);
        const joined = args.join(' ');
        return !joined.includes('--audit-log-path') || !joined.includes('--audit-policy-file');
      });
      return { passing: total - bad.length, total,
        entities: bad.map(p => `${p.metadata?.namespace}/${p.metadata?.name} (нет --audit-log-path/--audit-policy-file)`),
        fix: 'Добавьте в манифест kube-apiserver флаги --audit-log-path и --audit-policy-file. Без них события API не регистрируются (нарушение п.13.1).' };
    }},
  { id:'fstec-13.5', fstecRef:'13.1 (Tracee)', class:'5/4',
    cat:'Аудит', title:'13.1 — Tracee DaemonSet здоров на всех Ready-нодах',
    fn(d) {
      const traceeDS = findByName(allDaemonSets(d), 'tracee', 'tracee-bridge');
      if (traceeDS.length === 0) {
        return { passing: 0, total: 1,
          entities: ['DaemonSet tracee/tracee-bridge не найден ни в одном namespace'],
          fix: 'Разверните tracee/tracee-bridge как DaemonSet — он отвечает за регистрацию syscall-событий безопасности (п.13.1).' };
      }
      const nodesReady = readyNodes(d).length;
      const bad = traceeDS.filter(ds => {
        const desired = ds.status?.desiredNumberScheduled ?? 0;
        const ready = ds.status?.numberReady ?? 0;
        return ready < desired || ready < nodesReady;
      });
      return { passing: traceeDS.length - bad.length, total: traceeDS.length,
        entities: bad.map(ds => `${ds.metadata?.namespace}/${ds.metadata?.name} (ready ${ds.status?.numberReady||0}/${ds.status?.desiredNumberScheduled||0}, ready-нод: ${nodesReady})`),
        fix: 'Tracee DaemonSet должен быть Ready на всех Ready-нодах. Если поды падают — журнал событий неполный, что недопустимо для 5/4 класса.' };
    }},
  { id:'fstec-13.6', fstecRef:'13.1 (admission webhook)', class:'6/5/4',
    cat:'Аудит', title:'13.1 — sentry-audit ValidatingWebhookConfiguration зарегистрирован',
    fn(d) {
      const webhooks = d.snap?.validating_webhooks || [];
      const sentry = webhooks.filter(wh => {
        const n = (wh.metadata?.name || '').toLowerCase();
        const hooks = wh.webhooks || [];
        return n.includes('sentry') || n.includes('audit') ||
               hooks.some(h => (h.name || '').toLowerCase().includes('sentry') ||
                               (h.name || '').toLowerCase().includes('audit'));
      });
      const valid = sentry.filter(wh => (wh.webhooks || []).length > 0);
      return { passing: valid.length > 0 ? 1 : 0, total: 1,
        entities: valid.length > 0 ? [] : ['ValidatingWebhookConfiguration sentry-audit не найдена или пуста'],
        fix: 'Создайте ValidatingWebhookConfiguration для sentry-audit. Без неё admission-события не доставляются в журнал (нарушение п.13.1).' };
    }},
  { id:'fstec-13.7', fstecRef:'13.1 (anomaly-detector)', class:'5/4',
    cat:'Аудит', title:'13.1 — anomaly-detector запущен и обрабатывает события',
    fn(d) {
      const pods = allPods(d).filter(p => {
        const n = (p.metadata?.name || '').toLowerCase();
        const labels = p.metadata?.labels || {};
        const labelName = (labels['app.kubernetes.io/name'] || labels.app || '').toLowerCase();
        return n.includes('anomaly') || labelName.includes('anomaly');
      });
      if (pods.length === 0) {
        return { passing: 0, total: 1,
          entities: ['Pod anomaly-detector не найден'],
          fix: 'Разверните anomaly-detector — он регистрирует поведенческие отклонения (п.13.1).' };
      }
      const running = pods.filter(isPodRunning);
      const podsOk = running.length === pods.length;
      return { passing: podsOk ? 1 : 0, total: 1,
        entities: podsOk ? [] : [`не все поды Running (${running.length}/${pods.length})`],
        fix: 'anomaly-detector должен иметь все поды Running. Метрику events_processed_total и поток обработанных событий смотрите в Prometheus.' };
    }},
  { id:'fstec-13.8', fstecRef:'13.1 (forensic-watcher)', class:'5/4',
    cat:'Аудит', title:'13.1 — forensic-watcher DaemonSet здоров на всех Ready-нодах',
    fn(d) {
      const fwDS = findByName(allDaemonSets(d), 'forensic-watcher', 'forensic');
      if (fwDS.length === 0) {
        return { passing: 0, total: 1,
          entities: ['DaemonSet forensic-watcher не найден'],
          fix: 'Разверните forensic-watcher как DaemonSet — он собирает forensic-данные с каждой ноды (п.13.1).' };
      }
      const nodesReady = readyNodes(d).length;
      const bad = fwDS.filter(ds => {
        const desired = ds.status?.desiredNumberScheduled ?? 0;
        const ready = ds.status?.numberReady ?? 0;
        return ready < desired || ready < nodesReady;
      });
      return { passing: fwDS.length - bad.length, total: fwDS.length,
        entities: bad.map(ds => `${ds.metadata?.namespace}/${ds.metadata?.name} (ready ${ds.status?.numberReady||0}/${ds.status?.desiredNumberScheduled||0})`),
        fix: 'forensic-watcher должен работать на всех Ready-нодах кластера. Иначе теряется forensic-информация по части хостов.' };
    }},
];

const HOST_OS = [
  { id:'fstec-7.1', fstecRef:'7 (сертифицированная ОС)', class:'5/4',
    cat:'Хост ОС', title:'7 — Хостовая ОС из списка сертифицированных ФСТЭК',
    fn(d) {
      const nodes = d.snap?.nodes || [];
      const CERTIFIED = ['astra', 'redos', 'альт', 'alt linux', 'rosa'];
      const bad = nodes.filter(n => {
        const os = (n.status?.nodeInfo?.osImage || '').toLowerCase();
        return !CERTIFIED.some(s => os.includes(s));
      });
      return { passing: nodes.length - bad.length, total: Math.max(nodes.length,1),
        entities: bad.map(n => `${n.metadata?.name} (${n.status?.nodeInfo?.osImage || 'unknown'})`),
        fix: 'Хостовая ОС должна быть сертифицирована ФСТЭК (Astra Linux, RedOS, ОС «Альт», ROSA). Иначе сертификация средства контейнеризации невозможна.' };
    }},
  { id:'fstec-7.2', fstecRef:'7 (kernel)', class:'6/5/4',
    cat:'Хост ОС', title:'7 — Версия ядра не ниже 5.10 (поддержка eBPF/seccomp)',
    fn(d) {
      const MIN = [5, 10, 0];
      const nodes = d.snap?.nodes || [];
      const bad = nodes.filter(n => {
        const v = parseSemver(n.status?.nodeInfo?.kernelVersion);
        return !v || cmpSemver(v, MIN) < 0;
      });
      return { passing: nodes.length - bad.length, total: Math.max(nodes.length,1),
        entities: bad.map(n => `${n.metadata?.name} (kernel ${n.status?.nodeInfo?.kernelVersion || 'unknown'})`),
        fix: 'Обновите ядро до 5.10+. Старые ядра не поддерживают современные eBPF/seccomp, без которых Tracee/sentry-audit работают неполноценно.' };
    }},
  { id:'fstec-7.4', fstecRef:'7/8 (k8s version)', class:'6/5/4',
    cat:'Хост ОС', title:'7 — Версия kubelet/K8s не ниже 1.26 (поддерживаемая)',
    fn(d) {
      const MIN = [1, 26, 0];
      const nodes = d.snap?.nodes || [];
      const bad = nodes.filter(n => {
        const v = parseSemver(n.status?.nodeInfo?.kubeletVersion);
        return !v || cmpSemver(v, MIN) < 0;
      });
      return { passing: nodes.length - bad.length, total: Math.max(nodes.length,1),
        entities: bad.map(n => `${n.metadata?.name} (kubelet ${n.status?.nodeInfo?.kubeletVersion || 'unknown'})`),
        fix: 'Обновите kubelet до 1.26+. Старые версии k8s имеют известные CVE и не получают патчи безопасности.' };
    }},
  { id:'fstec-7.3', fstecRef:'7 (container runtime)', class:'5/4',
    cat:'Хост ОС', title:'7 — Container runtime: containerd ≥1.6 или CRI-O ≥1.24 (без dockershim)',
    fn(d) {
      const nodes = d.snap?.nodes || [];
      const MIN_CONTAINERD = [1, 6, 0];
      const MIN_CRIO = [1, 24, 0];
      const bad = nodes.filter(n => {
        const rt = (n.status?.nodeInfo?.containerRuntimeVersion || '').toLowerCase();
        if (rt.includes('docker') && !rt.includes('cri-dockerd')) return true;
        const v = parseSemver(rt);
        if (!v) return true;
        if (rt.includes('containerd')) return cmpSemver(v, MIN_CONTAINERD) < 0;
        if (rt.includes('cri-o')) return cmpSemver(v, MIN_CRIO) < 0;
        return true;
      });
      return { passing: nodes.length - bad.length, total: Math.max(nodes.length,1),
        entities: bad.map(n => `${n.metadata?.name} (${n.status?.nodeInfo?.containerRuntimeVersion || 'unknown'})`),
        fix: 'Используйте containerd ≥1.6 или CRI-O ≥1.24. Docker shim deprecated в k8s 1.24+ и не поддерживает современные требования безопасности (warning по п.7).' };
    }},
];

const ACCESS = [
  { id:'fstec-14.1', fstecRef:'14 (anonymous access)', class:'6/5/4',
    cat:'Доступ', title:'14 — Нет привязок ролей к system:anonymous / system:unauthenticated',
    fn(d) {
      const ANON = new Set(['system:anonymous', 'system:unauthenticated']);
      const all = [
        ...(d.snap?.cluster_role_bindings || []),
        ...(d.snap?.role_bindings || []),
      ];
      const bad = all.filter(b => (b.subjects || []).some(s =>
        ANON.has(s.name)));
      return { passing: all.length - bad.length, total: Math.max(all.length,1),
        entities: bad.map(b => `${b.metadata?.namespace ? b.metadata.namespace + '/' : ''}${b.metadata?.name} → ${b.roleRef?.name}`),
        fix: 'Удалите (Cluster)RoleBinding, в subjects которых есть system:anonymous / system:unauthenticated. Это даёт права кому угодно без аутентификации (нарушение п.14).' };
    }},
  { id:'fstec-14.2', fstecRef:'14 (cluster-admin scope)', class:'5/4',
    cat:'Доступ', title:'14 — cluster-admin привязан только к системным субъектам',
    fn(d) {
      const crbs = (d.snap?.cluster_role_bindings || [])
        .filter(b => b.roleRef?.name === 'cluster-admin');
      if (crbs.length === 0) {
        return { passing: 1, total: 1, entities: [],
          fix: 'cluster-admin не привязан ни к кому — ок.' };
      }
      const bad = crbs.filter(b => (b.subjects || []).some(s => {
        if (s.kind === 'ServiceAccount' && (s.namespace || '').startsWith('kube-')) return false;
        if (s.kind === 'Group' && (s.name === 'system:masters' || s.name === 'system:nodes')) return false;
        return true;
      }));
      return { passing: crbs.length - bad.length, total: crbs.length,
        entities: bad.map(b => `${b.metadata?.name} (${(b.subjects||[]).map(s=>`${s.kind}:${s.namespace ? s.namespace+'/' : ''}${s.name}`).join(', ')})`),
        fix: 'cluster-admin держите только на ServiceAccount в kube-* или встроенных system:masters/system:nodes. Для людей и приложений — отдельная роль с минимально нужными правами (п.14).' };
    }},
];

export { INTEGRITY, AUDIT, HOST_OS, ACCESS };
