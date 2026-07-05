import { appDeps, appPods, podContainers, wlContainers } from './checksCIS';
import { allPods, allNamespaces, allDaemonSets, readyNodes, findByName, parseSemver, cmpSemver } from './checksFSTEC_helpers';

const CONFIG = [
  { id:'fstec-11.1', fstecRef:'11', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Нет privileged-контейнеров',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c => c.securityContext?.privileged === true));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите securityContext.privileged=false. Privileged-контейнер имеет полный доступ к устройствам хоста (нарушение п.11).' };
    }},
  { id:'fstec-11.2', fstecRef:'11 (периферийные устройства)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Нет монтирования /dev, /proc, /sys из хоста',
    fn(d) {
      const pods = appPods(d);
      const DANGEROUS = ['/dev', '/proc', '/sys'];
      const bad = pods.filter(p => (p.spec?.volumes || []).some(v =>
        v.hostPath && DANGEROUS.some(d => v.hostPath.path?.startsWith(d))
      ));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Уберите hostPath-монтирования /dev/*, /proc/*, /sys/*. Это даёт контейнеру доступ к периферийным и блочным устройствам хоста.' };
    }},
  { id:'fstec-11.3', fstecRef:'11 (hostPath)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Минимизировано использование hostPath volumes',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => (p.spec?.volumes || []).some(v => v.hostPath));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'hostPath volumes дают контейнеру прямой доступ к файловой системе хоста. Используйте emptyDir, PVC или ConfigMap.' };
    }},
  { id:'fstec-11.4', fstecRef:'11 (ограничение ресурсов)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Установлены лимиты памяти (resources.limits.memory)',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c => !c.resources?.limits?.memory));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите resources.limits.memory во всех контейнерах. Без лимитов контейнер может исчерпать RAM хоста (нарушение п.11).' };
    }},
  { id:'fstec-11.5', fstecRef:'11 (ограничение ресурсов)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Установлены лимиты CPU (resources.limits.cpu)',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c => !c.resources?.limits?.cpu));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите resources.limits.cpu во всех контейнерах — для ограничения операций ввода-вывода и вычислительных ресурсов.' };
    }},
  { id:'fstec-11.6', fstecRef:'11 (read-only rootfs)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Корневая ФС монтируется только для чтения',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c =>
        c.securityContext?.readOnlyRootFilesystem !== true));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Явное требование п.11: readOnlyRootFilesystem=true. Пишите в emptyDir/PVC если нужна запись.' };
    }},
  { id:'fstec-11.7', fstecRef:'15.3 / 11 (запрет root)', class:'4',
    cat:'Конфигурация', title:'15.3 — Контейнеры не запускаются от root (для 4 класса)',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => {
        const spec = p.spec || {};
        if (spec.securityContext?.runAsNonRoot === true) return false;
        if (spec.securityContext?.runAsUser > 0) return false;
        return podContainers(p).some(c =>
          c.securityContext?.runAsNonRoot !== true &&
          !(c.securityContext?.runAsUser > 0));
      });
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Для 4 класса защиты п.15.3: контейнер не должен запускать процессы с правами администратора. Установите runAsNonRoot=true или runAsUser>0.' };
    }},
  { id:'fstec-11.8', fstecRef:'11 (privilege escalation)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Запрещена эскалация привилегий',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c =>
        c.securityContext?.allowPrivilegeEscalation !== false));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите allowPrivilegeEscalation=false. Это запрещает контейнеру получать дополнительные привилегии через setuid.' };
    }},
  { id:'fstec-11.9', fstecRef:'11 (capabilities)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Сброшены все Linux capabilities по умолчанию (drop: ALL)',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c => {
        const drop = c.securityContext?.capabilities?.drop || [];
        return !drop.some(x => String(x).toUpperCase() === 'ALL');
      }));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите securityContext.capabilities.drop=["ALL"] и add=[…] только необходимые. Минимизация capabilities — мера п.11.' };
    }},
  { id:'fstec-11.10', fstecRef:'11 (seccomp)', class:'5/4',
    cat:'Конфигурация', title:'11 — Установлен seccompProfile (минимум RuntimeDefault)',
    fn(d) {
      const pods = appPods(d);
      const ok = (type) => type === 'RuntimeDefault' || type === 'Localhost';
      const bad = pods.filter(p => {
        const podType = p.spec?.securityContext?.seccompProfile?.type;
        if (ok(podType)) return false;
        return podContainers(p).some(c => !ok(c.securityContext?.seccompProfile?.type));
      });
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите securityContext.seccompProfile.type=RuntimeDefault на уровне pod или каждого контейнера. Без seccomp фильтрация syscalls отключена.' };
    }},
  { id:'fstec-11.11', fstecRef:'11 (shareProcessNamespace)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Запрещён shareProcessNamespace между контейнерами пода',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => p.spec?.shareProcessNamespace === true);
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Уберите spec.shareProcessNamespace=true. Это позволяет контейнерам одного пода видеть процессы друг друга — нарушение изоляции п.11.' };
    }},
  { id:'fstec-11.12', fstecRef:'11 (SA token)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — automountServiceAccountToken=false на подах без обращений к API',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => {
        if (p.spec?.automountServiceAccountToken === false) return false;
        const sa = p.spec?.serviceAccountName;
        if (sa && sa !== 'default') return false;
        return true;
      });
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Для подов без обращений к kube-apiserver установите automountServiceAccountToken=false. Иначе токен SA доступен в /var/run/secrets/kubernetes.io.' };
    }},
  { id:'fstec-11.13', fstecRef:'11 (docker.sock)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Не монтируется /var/run/docker.sock из хоста',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => (p.spec?.volumes || []).some(v => {
        const path = v.hostPath?.path || '';
        return path.includes('docker.sock') || path === '/var/run/docker.sock';
      }));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Уберите hostPath с /var/run/docker.sock. Доступ к docker daemon = root на хосте, прямое нарушение п.11.' };
    }},
  { id:'fstec-11.14', fstecRef:'11 (CRI socket)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Не монтируется containerd/CRI-O сокет из хоста',
    fn(d) {
      const SOCKETS = ['containerd.sock', 'crio.sock', 'cri-dockerd.sock', '/run/containerd', '/run/crio'];
      const pods = appPods(d);
      const bad = pods.filter(p => (p.spec?.volumes || []).some(v => {
        const path = v.hostPath?.path || '';
        return SOCKETS.some(s => path.includes(s));
      }));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Уберите hostPath с containerd.sock / crio.sock / cri-dockerd.sock. Контейнер с доступом к runtime-сокету эквивалентен root на хосте.' };
    }},
  { id:'fstec-11.15', fstecRef:'11 (resources.requests)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Установлены resources.requests для CPU и памяти',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => podContainers(p).some(c =>
        !c.resources?.requests?.memory || !c.resources?.requests?.cpu));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Установите resources.requests.cpu и resources.requests.memory. Без них scheduler не учитывает реальные потребности и QoS пода = BestEffort.' };
    }},
  { id:'fstec-11.16', fstecRef:'11 (mandatory access control)', class:'5/4',
    cat:'Конфигурация', title:'11 — Установлен AppArmor или SELinux профиль',
    fn(d) {
      const isMacSet = sc => {
        if (!sc) return false;
        if (sc.seLinuxOptions && Object.keys(sc.seLinuxOptions).length > 0) return true;
        const aa = sc.appArmorProfile?.type;
        return aa === 'RuntimeDefault' || aa === 'Localhost';
      };
      const pods = appPods(d);
      const bad = pods.filter(p => {
        if (isMacSet(p.spec?.securityContext)) return false;
        const annotations = p.metadata?.annotations || {};
        return podContainers(p).some(c => {
          if (isMacSet(c.securityContext)) return false;
          const a = annotations[`container.apparmor.security.beta.kubernetes.io/${c.name}`] || '';
          if (a === 'runtime/default' || a.startsWith('localhost/')) return false;
          return true;
        });
      });
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Включите AppArmor (securityContext.appArmorProfile.type=RuntimeDefault или аннотация container.apparmor.security.beta.kubernetes.io/<container>=runtime/default) либо seLinuxOptions. Без MAC ограничения прав ПО держатся только на DAC, что не закрывает п.11.' };
    }},
  { id:'fstec-11.17', fstecRef:'11 (hostPort)', class:'6/5/4',
    cat:'Конфигурация', title:'11 — Не используется hostPort',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => podContainers(p).some(c =>
        (c.ports || []).some(port => port.hostPort && port.hostPort > 0)));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Уберите ports[].hostPort. Используйте Service или Ingress. hostPort нарушает сетевую изоляцию и режет переносимость пода между нодами.' };
    }},
  { id:'fstec-11.18', fstecRef:'11 (emptyDir.sizeLimit)', class:'5/4',
    cat:'Конфигурация', title:'11 — У всех emptyDir задан sizeLimit',
    fn(d) {
      const pods = appPods(d);
      const bad = pods.filter(p => (p.spec?.volumes || []).some(v =>
        v.emptyDir && !v.emptyDir.sizeLimit));
      return { passing: pods.length - bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Задайте volumes[].emptyDir.sizeLimit. Без него под может занять весь диск ноды и положить kubelet (DoS на инфраструктурный слой).' };
    }},
];

export { CONFIG };
