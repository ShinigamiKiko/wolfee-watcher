function DetailRow({ label, val, mono }) {
  if (!val && val !== 0) return null;
  return (
    <div className="al-detail-row">
      <span className="al-detail-lbl">{label}</span>
      <span className={`al-detail-val${mono?' al-detail-val--mono':''}`}>{val}</span>
    </div>
  );
}

export { DetailRow };
