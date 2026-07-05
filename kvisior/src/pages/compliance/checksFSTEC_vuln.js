import { appDeps, appPods, podContainers } from './checksCIS';
import { allPods } from './checksFSTEC_helpers';

const VULN = [
  { id:'fstec-10.1', fstecRef:'10.1', class:'6/5/4',
    cat:'Уязвимости', title:'10.1 — Сканирование образов на известные уязвимости',
    fn(d) {
      const imgs    = d.scan?.results || [];
      const scanned = imgs.filter(r => r.status === 'done');
      const total   = Math.max(imgs.length, 1);
      return { passing: scanned.length, total,
        entities: imgs.filter(r => r.status !== 'done').map(r=>`${r.name}:${r.tag} (${r.status || 'unknown'})`).filter(Boolean),
        fix: 'Все образы контейнеров должны регулярно сканироваться. Проверьте работу scanner-agent и доступность реестра.' };
    }},
  { id:'fstec-10.2', fstecRef:'10.2', class:'5/4',
    cat:'Уязвимости', title:'10.2 — Нет критичных уязвимостей (Critical) в образах',
    fn(d) {
      const scanned = (d.scan?.results || []).filter(r => r.status === 'done');
      const total   = Math.max(scanned.length, 1);
      const bad     = scanned.filter(r => (r.summary?.critical || 0) > 0);
      return { passing: total - bad.length, total,
        entities: bad.map(r => {
          const bdu = r.cves?.find(c => c.severity==='critical' && c.bduId)?.bduId;
          return `${r.name}:${r.tag} (${r.summary.critical} critical${bdu ? `, ${bdu}` : ''})`;
        }).filter(Boolean),
        fix: 'Для 5 и 4 классов защиты средство контейнеризации должно запрещать регистрацию образов с критичными уязвимостями. Обновите базовые образы.' };
    }},
  { id:'fstec-10.3', fstecRef:'10.2', class:'5/4',
    cat:'Уязвимости', title:'10.2 — Нет уязвимостей высокого уровня (High) в образах',
    fn(d) {
      const scanned = (d.scan?.results || []).filter(r => r.status === 'done');
      const total   = Math.max(scanned.length, 1);
      const bad     = scanned.filter(r => (r.summary?.high || 0) > 0);
      return { passing: total - bad.length, total,
        entities: bad.map(r => `${r.name}:${r.tag} (${r.summary.high} high)`).filter(Boolean),
        fix: 'Устраните уязвимости высокого уровня опасности в образах (requirements п.10.2).' };
    }},
  { id:'fstec-10.5', fstecRef:'10 (свежесть)', class:'6/5/4',
    cat:'Уязвимости', title:'10 — Сканы образов свежие (не старше 7 дней)',
    fn(d) {
      const scanned = (d.scan?.results || []).filter(r => r.status === 'done');
      if (scanned.length === 0) {
        return { passing: 0, total: 1,
          entities: ['Нет успешно просканированных образов'],
          fix: 'Запустите scanner-agent — без свежих сканов п.10 не выполняется.' };
      }
      const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
      const stale = scanned.filter(r => {
        const t = r.scannedAt ? Date.parse(r.scannedAt) : 0;
        return !t || t < cutoff;
      });
      return { passing: scanned.length - stale.length, total: scanned.length,
        entities: stale.map(r => {
          const t = r.scannedAt ? Date.parse(r.scannedAt) : 0;
          const days = t ? Math.round((Date.now() - t) / 86400000) : '?';
          return `${r.name}:${r.tag} (последний скан ${days} дн. назад)`;
        }),
        fix: 'Включите расписание сканирования (scanner-agent /schedule) минимум раз в неделю. Для 5/4 класса — раз в сутки.' };
    }},
  { id:'fstec-10.4', fstecRef:'10', class:'6/5/4',
    cat:'Уязвимости', title:'Покрытие БДУ ФСТЭК — есть ссылка на BDU-ID для уязвимостей',
    fn(d) {
      const allCVEs = [];
      for (const r of (d.scan?.results || [])) for (const c of (r.cves || [])) allCVEs.push(c);
      if (allCVEs.length === 0) {
        return { passing: 1, total: 1, entities: [],
          fix: 'Нет просканированных CVE — нечего мапить на БДУ. Запустите scanner-agent.' };
      }
      const withBDU = allCVEs.filter(c => c.bduId).length;
      const ok = withBDU > 0 ? 1 : 0;
      return { passing: ok, total: 1,
        entities: withBDU === 0 ? [`Ни один из ${allCVEs.length} CVE не сопоставлен с БДУ. Проверьте работу BDU-enricher в scanner-agent.`] : [],
        fix: 'Убедитесь что scanner-agent периодически скачивает архив БДУ ФСТЭК (bdu.fstec.ru). Отсутствие маппинга критично для отчётности перед регулятором.' };
    }},
];

export { VULN };
