import { jsPDF } from 'jspdf';
import { autoTable } from 'jspdf-autotable';
import regularUrl from 'dejavu-fonts-ttf/ttf/DejaVuSans.ttf?url';
import boldUrl from 'dejavu-fonts-ttf/ttf/DejaVuSans-Bold.ttf?url';

const FONT = 'DejaVuSans';
const MARGIN = 40;
const FOOTER = 28;

const INK = [17, 24, 39];
const MUTED = [107, 114, 128];
const LINE = [229, 231, 235];
const PANEL = [248, 250, 252];
const ACCENT = [37, 99, 235];

export const TONE = {
  critical: [185, 28, 28],
  high: [194, 65, 12],
  medium: [161, 98, 7],
  low: [37, 99, 235],
  unknown: MUTED,
  pass: [21, 128, 61],
  fail: [185, 28, 28],
  warn: [161, 98, 7],
  info: MUTED,
  ink: INK,
  muted: MUTED,
};

let fontCache = null;

async function fontData() {
  if (!fontCache) {
    fontCache = Promise.all([regularUrl, boldUrl].map(async url => {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`font ${url}: HTTP ${res.status}`);
      const bytes = new Uint8Array(await res.arrayBuffer());
      let bin = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(bin);
    })).catch(err => {
      fontCache = null;
      throw err;
    });
  }
  return fontCache;
}

function stamp(d = new Date()) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

export function fmtDate(d) {
  if (!d) return '—';
  const v = d instanceof Date ? d : new Date(d);
  if (isNaN(v.getTime())) return '—';
  return `${v.toLocaleDateString('ru-RU')} ${v.toLocaleTimeString('ru-RU')}`;
}

export function safeName(s) {
  return String(s || 'report').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'report';
}

export class Report {
  static async create({ title, subtitle, cluster, user, fileBase, orientation = 'portrait' }) {
    const [regular, bold] = await fontData();
    const doc = new jsPDF({ unit: 'pt', format: 'a4', orientation, compress: true });
    doc.addFileToVFS(`${FONT}.ttf`, regular);
    doc.addFont(`${FONT}.ttf`, FONT, 'normal');
    doc.addFileToVFS(`${FONT}-Bold.ttf`, bold);
    doc.addFont(`${FONT}-Bold.ttf`, FONT, 'bold');
    doc.setFont(FONT, 'normal');
    doc.setProperties({ title, subject: subtitle || title, creator: 'Wolfee-Watcher', author: user || 'Wolfee-Watcher' });
    const r = new Report(doc, { title, subtitle, cluster, user, fileBase });
    r.cover();
    return r;
  }

  constructor(doc, meta) {
    this.doc = doc;
    this.meta = meta;
    this.generatedAt = new Date();
    this.width = doc.internal.pageSize.getWidth();
    this.height = doc.internal.pageSize.getHeight();
    this.inner = this.width - MARGIN * 2;
    this.y = MARGIN;
  }

  font(style = 'normal', size = 9, color = INK) {
    this.doc.setFont(FONT, style);
    this.doc.setFontSize(size);
    this.doc.setTextColor(...color);
  }

  ensure(h) {
    if (this.y + h > this.height - MARGIN - FOOTER) {
      this.doc.addPage();
      this.y = MARGIN;
    }
  }

  cover() {
    const { doc } = this;
    doc.setFillColor(...ACCENT);
    doc.rect(0, 0, this.width, 4, 'F');
    this.font('bold', 8, ACCENT);
    doc.text('WOLFEE-WATCHER', MARGIN, this.y + 8, { charSpace: 1.2 });
    this.y += 30;
    this.font('bold', 20, INK);
    const lines = doc.splitTextToSize(this.meta.title, this.inner);
    doc.text(lines, MARGIN, this.y);
    this.y += lines.length * 24;
    if (this.meta.subtitle) {
      this.font('normal', 10, MUTED);
      const sub = doc.splitTextToSize(this.meta.subtitle, this.inner);
      doc.text(sub, MARGIN, this.y);
      this.y += sub.length * 13;
    }
    this.y += 6;
    const facts = [
      ['Cluster', this.meta.cluster || '—'],
      ['Generated', fmtDate(this.generatedAt)],
      ['By', this.meta.user || '—'],
    ];
    let x = MARGIN;
    facts.forEach(([k, v]) => {
      this.font('normal', 7.5, MUTED);
      doc.text(k.toUpperCase(), x, this.y, { charSpace: 0.6 });
      this.font('bold', 9.5, INK);
      doc.text(String(v), x, this.y + 13);
      x += Math.max(doc.getTextWidth(String(v)), 60) + 36;
    });
    this.y += 28;
    doc.setDrawColor(...LINE);
    doc.setLineWidth(0.8);
    doc.line(MARGIN, this.y, this.width - MARGIN, this.y);
    this.y += 20;
  }

  tiles(items) {
    const { doc } = this;
    const gap = 8;
    const n = items.length;
    const w = (this.inner - gap * (n - 1)) / n;
    const h = 52;
    this.ensure(h + 10);
    items.forEach((it, i) => {
      const x = MARGIN + i * (w + gap);
      doc.setFillColor(...PANEL);
      doc.setDrawColor(...LINE);
      doc.setLineWidth(0.6);
      doc.roundedRect(x, this.y, w, h, 4, 4, 'FD');
      if (it.color) {
        doc.setFillColor(...it.color);
        doc.rect(x, this.y + 6, 2.2, h - 12, 'F');
      }
      this.font('bold', 16, it.color || INK);
      doc.text(String(it.value ?? '—'), x + 12, this.y + 26);
      this.font('normal', 7.5, MUTED);
      doc.text(doc.splitTextToSize(String(it.label).toUpperCase(), w - 18)[0], x + 12, this.y + 41, { charSpace: 0.4 });
    });
    this.y += h + 18;
  }

  heading(text, sub) {
    this.ensure(sub ? 96 : 80);
    this.font('bold', 12.5, INK);
    this.doc.text(text, MARGIN, this.y + 10);
    this.y += 16;
    if (sub) {
      this.font('normal', 8.5, MUTED);
      const lines = this.doc.splitTextToSize(sub, this.inner);
      this.doc.text(lines, MARGIN, this.y + 6);
      this.y += lines.length * 11 + 2;
    }
    this.y += 6;
  }

  subheading(text, color = INK) {
    this.ensure(64);
    this.font('bold', 9.5, color);
    const lines = this.doc.splitTextToSize(text, this.inner);
    this.doc.text(lines, MARGIN, this.y + 8);
    this.y += lines.length * 12 + 6;
  }

  paragraph(text, { label, color = INK, size = 8.5, mono = false } = {}) {
    if (!text) return;
    if (label) {
      this.ensure(24);
      this.font('bold', 7.5, MUTED);
      this.doc.text(label.toUpperCase(), MARGIN, this.y + 6, { charSpace: 0.5 });
      this.y += 11;
    }
    this.font('normal', size, color);
    const lineH = size * 1.35;
    const lines = this.doc.splitTextToSize(String(text), this.inner - (mono ? 12 : 0));
    lines.forEach(line => {
      this.ensure(lineH);
      if (mono) {
        this.doc.setFillColor(...PANEL);
        this.doc.rect(MARGIN, this.y - 1, this.inner, lineH, 'F');
      }
      this.doc.text(line, MARGIN + (mono ? 6 : 0), this.y + size);
      this.y += lineH;
    });
    this.y += 6;
  }

  facts(pairs) {
    const rows = pairs.filter(([, v]) => v !== undefined && v !== null && v !== '');
    if (!rows.length) return;
    this.table({
      body: rows.map(([k, v]) => [k, String(v)]),
      columnStyles: { 0: { cellWidth: 110, textColor: MUTED, fontStyle: 'bold' } },
      plain: true,
    });
  }

  table({ head, body, columnStyles = {}, tone, plain = false }) {
    if (!body.length) return;
    this.ensure(40);
    autoTable(this.doc, {
      startY: this.y,
      head: head ? [head] : undefined,
      body,
      margin: { left: MARGIN, right: MARGIN, bottom: MARGIN + FOOTER },
      theme: plain ? 'plain' : 'grid',
      rowPageBreak: 'avoid',
      styles: {
        font: FONT, fontSize: 7.5, cellPadding: { top: 3.5, bottom: 3.5, left: 5, right: 5 },
        textColor: INK, lineColor: LINE, lineWidth: plain ? 0 : 0.5, overflow: 'linebreak', valign: 'top',
      },
      headStyles: { font: FONT, fontStyle: 'bold', fillColor: [241, 245, 249], textColor: INK, fontSize: 7.5, overflow: 'visible' },
      alternateRowStyles: plain ? undefined : { fillColor: [252, 252, 253] },
      columnStyles,
      didParseCell: tone ? (data => {
        if (data.section !== 'body') return;
        const c = tone(data.row.raw, data.column.index);
        if (c) {
          data.cell.styles.textColor = c;
          data.cell.styles.fontStyle = 'bold';
        }
      }) : undefined,
    });
    this.y = this.doc.lastAutoTable.finalY + 16;
  }

  note(text) {
    this.paragraph(text, { color: MUTED, size: 8 });
  }

  footer() {
    const { doc } = this;
    const total = doc.getNumberOfPages();
    for (let i = 1; i <= total; i++) {
      doc.setPage(i);
      doc.setDrawColor(...LINE);
      doc.setLineWidth(0.5);
      doc.line(MARGIN, this.height - MARGIN + 4, this.width - MARGIN, this.height - MARGIN + 4);
      this.font('normal', 7, MUTED);
      doc.text(`Wolfee-Watcher · ${this.meta.title} · ${this.meta.cluster || ''}`, MARGIN, this.height - MARGIN + 16);
      doc.text(`Page ${i} of ${total}`, this.width - MARGIN, this.height - MARGIN + 16, { align: 'right' });
    }
  }

  save() {
    this.footer();
    const name = `${safeName(this.meta.fileBase)}_${safeName(this.meta.cluster)}_${stamp(this.generatedAt)}.pdf`;
    this.doc.save(name);
    return name;
  }
}
