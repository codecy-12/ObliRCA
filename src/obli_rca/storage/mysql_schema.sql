-- MySQL 8.x schema for the paper's deployment shape.
-- The prototype's default runtime backend is SQLite; this DDL documents the
-- separated obligation-library and investigation tables and can be used when
-- deploying the stores on MySQL.
--
-- Note: the Python stores currently use SQLite-style UPSERT statements.  For a
-- MySQL deployment, replace those with ON DUPLICATE KEY UPDATE (the table
-- names and columns are identical).

CREATE TABLE IF NOT EXISTS obl_entries (
  id VARCHAR(128) PRIMARY KEY,
  category VARCHAR(128) NOT NULL,
  category_id INT NOT NULL DEFAULT 0,
  version VARCHAR(32) NOT NULL,
  semantic_hash VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'accepted',
  payload LONGTEXT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  KEY idx_obl_entries_hash (semantic_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS obl_graphs (
  entry_id VARCHAR(128) NOT NULL,
  graph_id VARCHAR(64) NOT NULL,
  semantic_hash VARCHAR(64) NOT NULL,
  payload LONGTEXT NOT NULL,
  PRIMARY KEY (entry_id, graph_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS obl_cases (
  entry_id VARCHAR(128) NOT NULL,
  case_ref VARCHAR(160) NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'source',
  source VARCHAR(255) NOT NULL DEFAULT '',
  PRIMARY KEY (entry_id, case_ref, role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inv_investigations (
  id VARCHAR(160) PRIMARY KEY,
  scenario_id VARCHAR(128) NOT NULL,
  source_version VARCHAR(64) NOT NULL DEFAULT '',
  status VARCHAR(32) NOT NULL DEFAULT 'running',
  created_at VARCHAR(40) NOT NULL,
  metadata LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inv_framework (
  investigation_id VARCHAR(160) NOT NULL,
  node_id VARCHAR(160) NOT NULL,
  app VARCHAR(128) NOT NULL,
  source_version VARCHAR(64) NOT NULL DEFAULT '',
  file VARCHAR(512) NOT NULL,
  function VARCHAR(255) NOT NULL,
  start_line INT NOT NULL DEFAULT 0,
  end_line INT NOT NULL DEFAULT 0,
  kind VARCHAR(64) NOT NULL DEFAULT 'function_slice',
  snippet LONGTEXT NOT NULL,
  event_ids LONGTEXT NOT NULL,
  parent_id VARCHAR(160),
  metadata LONGTEXT NOT NULL,
  PRIMARY KEY (investigation_id, node_id),
  KEY idx_inv_framework_app (investigation_id, app)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inv_log_refs (
  investigation_id VARCHAR(160) NOT NULL,
  event_id VARCHAR(64) NOT NULL,
  app VARCHAR(128) NOT NULL,
  tid INT NOT NULL DEFAULT 0,
  syscall VARCHAR(64) NOT NULL,
  object VARCHAR(512),
  payload LONGTEXT NOT NULL,
  PRIMARY KEY (investigation_id, event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inv_hypotheses (
  investigation_id VARCHAR(160) NOT NULL,
  hypothesis_id VARCHAR(160) NOT NULL,
  obligation_id VARCHAR(128) NOT NULL,
  location VARCHAR(512) NOT NULL,
  mechanism LONGTEXT NOT NULL,
  gap_type VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  confidence DOUBLE NOT NULL DEFAULT 0,
  payload LONGTEXT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  PRIMARY KEY (investigation_id, hypothesis_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inv_feedback (
  investigation_id VARCHAR(160) NOT NULL,
  hypothesis_id VARCHAR(160) NOT NULL,
  round INT NOT NULL,
  request LONGTEXT NOT NULL,
  response LONGTEXT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  PRIMARY KEY (investigation_id, hypothesis_id, round)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS inv_rankings (
  investigation_id VARCHAR(160) NOT NULL,
  hypothesis_id VARCHAR(160) NOT NULL,
  rank INT NOT NULL,
  score DOUBLE NOT NULL DEFAULT 0,
  explanation LONGTEXT NOT NULL,
  fix LONGTEXT NOT NULL,
  PRIMARY KEY (investigation_id, hypothesis_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
