package schema

const PartitionedTables = "container_logs, audit_events"

var v0009PartitionDDL = []string{

	`DO $$
	DECLARE
	  r          RECORD;
	  seqname    TEXT;
	  lo         TIMESTAMPTZ;
	  hi         TIMESTAMPTZ;
	  cur        TIMESTAMPTZ;
	  maxid      BIGINT;
	BEGIN
	  FOR r IN SELECT * FROM (VALUES
	    ('container_logs',
	     'id BIGSERIAL, ts TIMESTAMPTZ NOT NULL, ns TEXT NOT NULL, pod TEXT NOT NULL,
	      container TEXT NOT NULL, log TEXT NOT NULL,
	      cluster_id TEXT NOT NULL DEFAULT ''default'', PRIMARY KEY (id, ts)',
	     'id, ts, ns, pod, container, log, cluster_id'),
	    ('audit_events',
	     'id BIGSERIAL, ts TIMESTAMPTZ NOT NULL DEFAULT NOW(), "user" TEXT, kind TEXT,
	      ns TEXT, resource TEXT, data JSONB NOT NULL,
	      cluster_id TEXT NOT NULL DEFAULT ''default'', PRIMARY KEY (id, ts)',
	     'id, ts, "user", kind, ns, resource, data, cluster_id')
	  ) AS v(tbl, cols, copycols) LOOP

	    IF to_regclass(r.tbl) IS NULL THEN CONTINUE; END IF;
	    IF EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid = r.tbl::regclass) THEN
	      CONTINUE;
	    END IF;

	    seqname := pg_get_serial_sequence(r.tbl, 'id');

	    EXECUTE format('ALTER TABLE %I RENAME TO %I', r.tbl, r.tbl || '_legacy');
	    IF seqname IS NOT NULL THEN
	      EXECUTE format('ALTER SEQUENCE %s RENAME TO %I', seqname, r.tbl || '_legacy_id_seq');
	    END IF;

	    EXECUTE format('CREATE TABLE %I (%s) PARTITION BY RANGE (ts)', r.tbl, r.cols);

	    EXECUTE format('SELECT date_trunc(''hour'', MIN(ts)), date_trunc(''hour'', MAX(ts)) FROM %I',
	                   r.tbl || '_legacy') INTO lo, hi;
	    IF lo IS NULL THEN
	      lo := date_trunc('hour', NOW());
	      hi := lo;
	    END IF;
	    cur := lo;
	    WHILE cur <= hi LOOP
	      EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
	        r.tbl || '_p' || to_char(cur AT TIME ZONE 'UTC', 'YYYYMMDDHH24'),
	        r.tbl, cur, cur + INTERVAL '1 hour');
	      cur := cur + INTERVAL '1 hour';
	    END LOOP;

	    EXECUTE format('INSERT INTO %I (%s) SELECT %s FROM %I',
	                   r.tbl, r.copycols, r.copycols, r.tbl || '_legacy');

	    EXECUTE format('SELECT COALESCE(MAX(id), 0) FROM %I', r.tbl) INTO maxid;
	    IF maxid > 0 THEN
	      PERFORM setval(pg_get_serial_sequence(r.tbl, 'id'), maxid);
	    END IF;

	    EXECUTE format('DROP TABLE %I', r.tbl || '_legacy');
	  END LOOP;
	END $$`,

	`CREATE INDEX IF NOT EXISTS idx_container_logs_lookup
	 ON container_logs(cluster_id, ns, pod, container, ts)`,
	`CREATE INDEX IF NOT EXISTS idx_container_logs_ts ON container_logs(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_cluster_id ON audit_events(cluster_id, id)`,

	`ALTER TABLE alerts SET (
	  autovacuum_vacuum_scale_factor = 0.0,
	  autovacuum_vacuum_threshold    = 200,
	  autovacuum_vacuum_cost_delay   = 0,
	  autovacuum_analyze_scale_factor = 0.0,
	  autovacuum_analyze_threshold   = 500,
	  fillfactor = 70
	)`,
	`ALTER TABLE forensic_events SET (
	  autovacuum_vacuum_scale_factor = 0.02,
	  autovacuum_vacuum_threshold    = 1000,
	  autovacuum_vacuum_cost_delay   = 0
	)`,
	`ALTER TABLE anomaly_events SET (
	  autovacuum_vacuum_scale_factor = 0.05,
	  autovacuum_vacuum_threshold    = 1000
	)`,
	`ALTER TABLE kvisior_violations SET (
	  autovacuum_vacuum_scale_factor = 0.05,
	  autovacuum_vacuum_threshold    = 1000
	)`,

	`CREATE OR REPLACE FUNCTION ww_maintain_partitions(
	  retention_hours INT DEFAULT 26,
	  ahead_hours     INT DEFAULT 48
	) RETURNS TABLE (created INT, dropped INT)
	LANGUAGE plpgsql
	SECURITY DEFINER
	SET search_path = public
	SET timezone = 'UTC'
	AS $$
	DECLARE
	  tbl    TEXT;
	  part   TEXT;
	  lo     TIMESTAMPTZ;
	  h      INT;
	  base   TIMESTAMPTZ := date_trunc('hour', NOW());
	  cutoff TIMESTAMPTZ := date_trunc('hour', NOW()) - make_interval(hours => retention_hours);
	BEGIN
	  created := 0;
	  dropped := 0;
	  FOREACH tbl IN ARRAY ARRAY['container_logs','audit_events'] LOOP
	    IF to_regclass(tbl) IS NULL THEN CONTINUE; END IF;
	    IF NOT EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid = tbl::regclass) THEN
	      CONTINUE;
	    END IF;

	    FOR h IN 0..(retention_hours + ahead_hours) LOOP
	      lo   := base - make_interval(hours => retention_hours - h);
	      part := tbl || '_p' || to_char(lo, 'YYYYMMDDHH24');
	      IF to_regclass(part) IS NULL THEN
	        EXECUTE format('CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
	                       part, tbl, lo, lo + INTERVAL '1 hour');
	        created := created + 1;
	      END IF;
	    END LOOP;

	    FOR part IN
	      SELECT c.relname FROM pg_class c
	      JOIN pg_inherits i ON i.inhrelid = c.oid
	      JOIN pg_class p    ON p.oid = i.inhparent
	      WHERE p.relname = tbl AND c.relname ~ '_p[0-9]{10}$'
	    LOOP
	      IF to_timestamp(right(part, 10), 'YYYYMMDDHH24') + INTERVAL '1 hour' <= cutoff THEN
	        EXECUTE format('DROP TABLE IF EXISTS %I', part);
	        dropped := dropped + 1;
	      END IF;
	    END LOOP;
	  END LOOP;
	  RETURN NEXT;
	END $$`,

	`SELECT ww_maintain_partitions()`,
}
