package schema

func init() { DDL = append(DDL, v0022DDL...) }

var v0022DDL = []string{
	`ALTER TABLE forensic_events ADD COLUMN IF NOT EXISTS container_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE forensic_events ADD COLUMN IF NOT EXISTS baseline BOOLEAN NOT NULL DEFAULT FALSE`,
}
