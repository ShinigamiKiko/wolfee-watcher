import { allPods, readyNodes } from './checksFSTEC_helpers';
import { appPods } from './checksCIS';

const ISOLATION = [
  { id:'fstec-9.1', fstecRef:'9 (изоляция PID)', class:'5/4',
    cat:'Изоляция', title:'Контейнеры не используют хостовой PID namespace',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => p.spec?.hostPID === true);
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p => `${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите hostPID=false во всех pod spec. hostPID=true нарушает изоляцию пространства идентификаторов процессов (п.9 приказа № 118).' };
    }},
  { id:'fstec-9.2', fstecRef:'9 (изоляция IPC)', class:'5/4',
    cat:'Изоляция', title:'Контейнеры не используют хостовой IPC namespace',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => p.spec?.hostIPC === true);
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p => `${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите hostIPC=false. hostIPC=true нарушает изоляцию пространства имён межпроцессного взаимодействия.' };
    }},
  { id:'fstec-9.3', fstecRef:'9 (изоляция сети)', class:'5/4',
    cat:'Изоляция', title:'Контейнеры не используют хостовой network namespace',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => p.spec?.hostNetwork === true);
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p => `${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите hostNetwork=false. hostNetwork=true нарушает изоляцию сетевого пространства имён.' };
    }},
  { id:'fstec-9.4', fstecRef:'9 (PodSecurityStandards)', class:'5/4',
    cat:'Изоляция', title:'9 — На рабочих namespace установлен label pod-security.kubernetes.io/enforce',
    fn(d) {
      const wlNS = allNamespaces(d).filter(n => n.metadata?.name && !SYS_NS.has(n.metadata.name));
      const bad = wlNS.filter(n => {
        const lvl = n.metadata?.labels?.['pod-security.kubernetes.io/enforce'];
        return lvl !== 'restricted' && lvl !== 'baseline';
      });
      return { passing: wlNS.length - bad.length, total: Math.max(wlNS.length,1),
        entities: bad.map(n => `${n.metadata.name} (label enforce отсутствует или privileged)`),
        fix: 'kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted. Без enforce-метки PSS изоляция между подами на admission-уровне не обеспечивается.' };
    }},
  { id:'fstec-9.5', fstecRef:'9 (изоляция сетевых namespace)', class:'5/4',
    cat:'Изоляция', title:'9 — На каждом workload namespace есть NetworkPolicy default-deny',
    fn(d) {
      const wlNamesArr = allNamespaces(d)
        .map(n => n.metadata?.name)
        .filter(n => n && !SYS_NS.has(n));
      const policies = d.snap?.network_policies || [];
      const covered = new Set();
      for (const np of policies) {
        const sel = np.spec?.podSelector;
        const empty = sel && (!sel.matchLabels || Object.keys(sel.matchLabels).length === 0)
                          && (!sel.matchExpressions || sel.matchExpressions.length === 0);
        const types = np.spec?.policyTypes || [];
        const ingressDenied = types.includes('Ingress') && (!np.spec?.ingress || np.spec.ingress.length === 0);
        if (empty && ingressDenied) covered.add(np.metadata?.namespace);
      }
      const bad = wlNamesArr.filter(ns => !covered.has(ns));
      return { passing: wlNamesArr.length - bad.length, total: Math.max(wlNamesArr.length,1),
        entities: bad.map(ns => `${ns} (нет default-deny NetworkPolicy)`),
        fix: 'Создайте NetworkPolicy с podSelector:{} и policyTypes:[Ingress] без правил — это default-deny. Без неё все поды namespace могут общаться (нарушение п.9).' };
    }},
  { id:'fstec-9.6', fstecRef:'9 (runtimeClass)', class:'4',
    cat:'Изоляция', title:'9 — Для критичных workload указан runtimeClassName (warning, 4 класс)',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => !p.spec?.runtimeClassName);
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p => `${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Для 4 класса защиты желательно указывать pod.spec.runtimeClassName (например, runc по умолчанию или gvisor/kata для усиленной изоляции). Это warning, а не fail.' };
    }},
];

export { ISOLATION };
