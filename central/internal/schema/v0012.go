package schema

func init() {
	DDL = append(DDL, v0012DDL...)
	DDL = append(DDL, v0012PartitionDDL...)
}

var v0012DDL = []string{

	`CREATE TABLE IF NOT EXISTS clusters (
	id           TEXT PRIMARY KEY,
	name         TEXT NOT NULL,
	description  TEXT NOT NULL DEFAULT '',
	enabled      BOOLEAN NOT NULL DEFAULT TRUE,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_seen_at TIMESTAMPTZ
)`,
	`ALTER TABLE clusters ADD COLUMN IF NOT EXISTS endpoint TEXT NOT NULL DEFAULT ''`,

	`DO $$
	DECLARE t TEXT;
	BEGIN
	  FOREACH t IN ARRAY ARRAY[
	    'alerts','kvisior_violations','violation_acks','audit_events','container_logs',
	    'forensic_events','forensic_watches','anomaly_events','anomaly_silents',
	    'honeypot_events','honeypot_hidden_events','image_scans','image_histories',
	    'scanner_state','audit_runs','network_baselines','pod_syscall_watches',
	    'log_cursors','snapshot_cache','binary_exec_events','image_scan_workloads'
	  ] LOOP
	    IF to_regclass(t) IS NOT NULL THEN
	      EXECUTE format(
	        'ALTER TABLE %I ADD COLUMN IF NOT EXISTS cluster_id TEXT NOT NULL DEFAULT ''default''', t);
	    END IF;
	  END LOOP;
	END $$`,

	`DO $$
	DECLARE
	  r RECORD;
	  pk TEXT;
	BEGIN
	  FOR r IN SELECT * FROM (VALUES
	    ('violation_acks',         'cluster_id, key'),
	    ('forensic_watches',       'cluster_id, key'),
	    ('anomaly_silents',        'cluster_id, type, key'),
	    ('honeypot_events',        'cluster_id, namespace, honeypot, event_id'),
	    ('honeypot_hidden_events', 'cluster_id, namespace, honeypot, event_id'),
	    ('image_scans',            'cluster_id, image'),
	    ('image_histories',        'cluster_id, image'),
	    ('scanner_state',          'cluster_id, key'),
	    ('network_baselines',      'cluster_id, key'),
	    ('pod_syscall_watches',    'cluster_id, pod_key'),
	    ('log_cursors',            'cluster_id, key'),
	    ('snapshot_cache',         'cluster_id, key')
	  ) AS v(tbl, cols) LOOP
	    IF to_regclass(r.tbl) IS NULL THEN CONTINUE; END IF;
	    IF EXISTS (
	      SELECT 1 FROM pg_index i
	      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
	      WHERE i.indrelid = r.tbl::regclass AND i.indisprimary AND a.attname = 'cluster_id'
	    ) THEN CONTINUE; END IF;
	    SELECT conname INTO pk FROM pg_constraint
	     WHERE conrelid = r.tbl::regclass AND contype = 'p';
	    IF pk IS NOT NULL THEN
	      EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.tbl, pk);
	    END IF;
	    EXECUTE format('ALTER TABLE %I ADD PRIMARY KEY (%s)', r.tbl, r.cols);
	  END LOOP;
	END $$`,

	`DROP INDEX IF EXISTS idx_kv_viol_fp`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_kv_viol_fp
	 ON kvisior_violations(cluster_id, fingerprint) WHERE fingerprint != ''`,

	`DROP INDEX IF EXISTS idx_anomaly_events_ext_id`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_anomaly_events_ext_id
	 ON anomaly_events(cluster_id, ext_id)`,

	`DROP INDEX IF EXISTS idx_binary_exec_events_event_hash_key`,
	`DO $$
	DECLARE c TEXT;
	BEGIN
	  IF to_regclass('binary_exec_events') IS NULL THEN RETURN; END IF;
	  SELECT conname INTO c FROM pg_constraint
	   WHERE conrelid = 'binary_exec_events'::regclass AND contype = 'u'
	     AND pg_get_constraintdef(oid) LIKE '%event_hash%'
	     AND pg_get_constraintdef(oid) NOT LIKE '%cluster_id%';
	  IF c IS NOT NULL THEN
	    EXECUTE format('ALTER TABLE binary_exec_events DROP CONSTRAINT %I', c);
	  END IF;
	END $$`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_binary_exec_events_hash
	 ON binary_exec_events(cluster_id, event_hash)`,

	`DO $$
	DECLARE c TEXT;
	BEGIN
	  IF to_regclass('image_scan_workloads') IS NULL THEN RETURN; END IF;
	  SELECT conname INTO c FROM pg_constraint
	   WHERE conrelid = 'image_scan_workloads'::regclass AND contype = 'u'
	     AND pg_get_constraintdef(oid) NOT LIKE '%cluster_id%';
	  IF c IS NOT NULL THEN
	    EXECUTE format('ALTER TABLE image_scan_workloads DROP CONSTRAINT %I', c);
	  END IF;
	END $$`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_image_scan_workloads_dedup
	 ON image_scan_workloads(cluster_id, image, namespace, pod_uid, observed_at)`,

	`DROP INDEX IF EXISTS idx_forensic_events_dedup`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_forensic_events_dedup
	 ON forensic_events(cluster_id, ns, pod, path, op, snapped_at)`,

	`DO $$
	DECLARE
	  t TEXT;
	  found BOOLEAN := FALSE;
	BEGIN
	  FOREACH t IN ARRAY ARRAY[
	    'alerts','kvisior_violations','audit_events','binary_exec_events',
	    'anomaly_events','image_scans','honeypot_events','forensic_events'
	  ] LOOP
	    IF to_regclass(t) IS NOT NULL THEN
	      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I WHERE cluster_id = ''default'')', t) INTO found;
	      EXIT WHEN found;
	    END IF;
	  END LOOP;
	  IF found THEN
	    INSERT INTO clusters (id, name, description)
	    VALUES ('default', 'default', 'Data recorded before clusters were introduced')
	    ON CONFLICT (id) DO NOTHING;
	  END IF;
	END $$`,

	`CREATE INDEX IF NOT EXISTS idx_alerts_cluster_ts        ON alerts(cluster_id, ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_kv_viol_cluster_ts       ON kvisior_violations(cluster_id, ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_anomaly_events_cluster   ON anomaly_events(cluster_id, id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_runs_cluster       ON audit_runs(cluster_id, tool, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_forensic_events_cluster  ON forensic_events(cluster_id, ns, pod, ts)`,

	`CREATE INDEX IF NOT EXISTS idx_binary_exec_events_cluster_lookup
	 ON binary_exec_events(cluster_id, ns, pod, pod_uid, ts DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_binary_exec_events_cluster_cursor
	 ON binary_exec_events(cluster_id, ns, pod, id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_binary_exec_events_cluster_syscall
	 ON binary_exec_events(cluster_id, ns, pod, syscall, id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_image_scan_workloads_cluster_observed
	 ON image_scan_workloads(cluster_id, image, observed_at DESC)`,
}
