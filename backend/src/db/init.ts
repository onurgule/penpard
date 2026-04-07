import Database, { Database as DatabaseType } from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { logger } from '../utils/logger';

// Get consistent database path across CLI, Electron, and standalone backend
function getDefaultDbPath(): string {
  let appDataPath: string;

  if (process.platform === 'win32') {
    appDataPath = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  } else if (process.platform === 'darwin') {
    appDataPath = path.join(os.homedir(), 'Library', 'Application Support');
  } else {
    appDataPath = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  }

  return path.join(appDataPath, 'penpard', 'data', 'penpard.db');
}

const DB_PATH = process.env.DATABASE_PATH || getDefaultDbPath();

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

export const db: DatabaseType = new Database(DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

export async function initDatabase(): Promise<void> {
  logger.info('Initializing database...');
  console.log(`📁 Database path: ${DB_PATH}`);

  // Create tables
  db.exec(`
    -- Users table
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('super_admin', 'admin', 'user')),
      credits INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Whitelists table
    CREATE TABLE IF NOT EXISTS whitelists (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_pattern TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- LLM Configuration table
    CREATE TABLE IF NOT EXISTS llm_config (
        provider TEXT PRIMARY KEY,
        api_key TEXT,
        model TEXT,
        is_active INTEGER DEFAULT 0,
        is_online INTEGER DEFAULT 0,
        settings_json TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- MCP Servers table
    CREATE TABLE IF NOT EXISTS mcp_servers (
        name TEXT PRIMARY KEY,
        command TEXT NOT NULL,
        args TEXT,
        env_vars TEXT,
        status TEXT DEFAULT 'stopped',
        is_enabled INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Settings table (key-value store for prompts, logo path, etc.)
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Scans table
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('web', 'mobile')),
      target TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      burp_scan_id TEXT,
      mobsf_hash TEXT,
      
      -- New Antigravity Fields
      llm_provider TEXT,
      rate_limit INTEGER DEFAULT 5,
      recursion_depth INTEGER DEFAULT 2,
      use_nuclei INTEGER DEFAULT 0,
      use_ffuf INTEGER DEFAULT 0,
      idor_users_json TEXT,
      orchestrator_logs_path TEXT,

      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      error_message TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Vulnerabilities table
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      cvss_score REAL,
      cvss_vector TEXT,
      cwe TEXT,
      cve TEXT,
      request TEXT,
      response TEXT,
      screenshot_path TEXT,
      evidence TEXT,
      remediation TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Reports table
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT UNIQUE NOT NULL,
      file_path TEXT NOT NULL,
      format TEXT DEFAULT 'markdown',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Token usage tracking table
    CREATE TABLE IF NOT EXISTS token_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      total_tokens INTEGER NOT NULL DEFAULT 0,
      scan_id TEXT,
      context TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Scan logs table (persists agent logs for completed scans)
    CREATE TABLE IF NOT EXISTS scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Scan chat messages (persists human commands + PenPard responses)
    CREATE TABLE IF NOT EXISTS scan_chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('human', 'assistant')),
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
    CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
    CREATE INDEX IF NOT EXISTS idx_whitelists_user_id ON whitelists(user_id);
    CREATE INDEX IF NOT EXISTS idx_token_usage_created_at ON token_usage(created_at);
    CREATE INDEX IF NOT EXISTS idx_token_usage_provider_model ON token_usage(provider, model);
    CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_chat_messages_scan_id ON scan_chat_messages(scan_id);

    -- Report analyses (Red Team Mind Reconstruction)
    CREATE TABLE IF NOT EXISTS report_analyses (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      file_path TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','parsing','analyzing','completed','failed')),
      report_metadata_json TEXT,
      behavioral_profile_json TEXT,
      defensive_intel_json TEXT,
      error_message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Analysis findings (one per extracted vulnerability)
    CREATE TABLE IF NOT EXISTS analysis_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analysis_id TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      description TEXT,
      poc_steps_json TEXT,
      raw_http_requests_json TEXT,
      payloads_json TEXT,
      evidence_json TEXT,
      recommendation TEXT,
      discovery_method TEXT,
      reasoning_chain_json TEXT,
      skill_estimation TEXT,
      automation_probability REAL,
      defensive_insights_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (analysis_id) REFERENCES report_analyses(id) ON DELETE CASCADE
    );

    -- Analysis logs (processing progress)
    CREATE TABLE IF NOT EXISTS analysis_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analysis_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (analysis_id) REFERENCES report_analyses(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_report_analyses_user_id ON report_analyses(user_id);
    CREATE INDEX IF NOT EXISTS idx_analysis_findings_analysis_id ON analysis_findings(analysis_id);
    CREATE INDEX IF NOT EXISTS idx_analysis_logs_analysis_id ON analysis_logs(analysis_id);

    -- Mindset TTP library (learned tactics from reports)
    CREATE TABLE IF NOT EXISTS mindset_ttps (
      id TEXT PRIMARY KEY,
      source_analysis_id TEXT NOT NULL,
      source_finding_id INTEGER,
      title TEXT NOT NULL,
      vulnerability_class TEXT NOT NULL,
      discovery_strategy_json TEXT,
      preconditions_json TEXT,
      entrypoint_hints_json TEXT,
      request_templates_json TEXT,
      payload_templates_json TEXT,
      verification_criteria_json TEXT,
      confidence REAL DEFAULT 0.5,
      generalization_notes TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (source_analysis_id) REFERENCES report_analyses(id) ON DELETE CASCADE
    );

    -- Aggregated mindset profile
    CREATE TABLE IF NOT EXISTS mindset_profile (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      profile_json TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_mindset_ttps_analysis ON mindset_ttps(source_analysis_id);
    CREATE INDEX IF NOT EXISTS idx_mindset_ttps_class ON mindset_ttps(vulnerability_class);

    -- TTP Test Playbook cache (AI-generated testing guides)
    CREATE TABLE IF NOT EXISTS ttp_test_playbooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ttp_id TEXT NOT NULL,
      content TEXT NOT NULL,
      model TEXT,
      tokens INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ttp_id) REFERENCES mindset_ttps(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_ttp_playbooks_ttp ON ttp_test_playbooks(ttp_id);

    -- Presence Scan Runs
    CREATE TABLE IF NOT EXISTS presence_scan_runs (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      ttp_id TEXT NOT NULL,
      ttp_title TEXT,
      status TEXT DEFAULT 'pending',
      targets_count INTEGER DEFAULT 0,
      results_present INTEGER DEFAULT 0,
      results_likely INTEGER DEFAULT 0,
      results_absent INTEGER DEFAULT 0,
      results_unknown INTEGER DEFAULT 0,
      started_at DATETIME,
      finished_at DATETIME,
      error_message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Per-target results for each run
    CREATE TABLE IF NOT EXISTS presence_scan_targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      target_raw TEXT NOT NULL,
      target_url TEXT NOT NULL,
      target_host TEXT,
      target_port INTEGER,
      target_scheme TEXT,
      status TEXT DEFAULT 'pending',
      verdict TEXT,
      verdict_reason TEXT,
      evidence_json TEXT,
      request_sent TEXT,
      response_excerpt TEXT,
      checked_at DATETIME,
      FOREIGN KEY (run_id) REFERENCES presence_scan_runs(id) ON DELETE CASCADE
    );

    -- Audit log per run
    CREATE TABLE IF NOT EXISTS presence_scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (run_id) REFERENCES presence_scan_runs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_psr_user ON presence_scan_runs(user_id);
    CREATE INDEX IF NOT EXISTS idx_psr_ttp ON presence_scan_runs(ttp_id);
    CREATE INDEX IF NOT EXISTS idx_pst_run ON presence_scan_targets(run_id);
    CREATE INDEX IF NOT EXISTS idx_pst_verdict ON presence_scan_targets(verdict);
    CREATE INDEX IF NOT EXISTS idx_psl_run ON presence_scan_logs(run_id);

    -- Join table: multiple TTPs per presence scan run
    CREATE TABLE IF NOT EXISTS presence_scan_run_ttps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      ttp_id TEXT NOT NULL,
      ttp_title TEXT,
      FOREIGN KEY (run_id) REFERENCES presence_scan_runs(id) ON DELETE CASCADE,
      UNIQUE(run_id, ttp_id)
    );

    CREATE INDEX IF NOT EXISTS idx_psrt_run ON presence_scan_run_ttps(run_id);
    CREATE INDEX IF NOT EXISTS idx_psrt_ttp ON presence_scan_run_ttps(ttp_id);

    -- PenPard Browser sessions
    CREATE TABLE IF NOT EXISTS browser_sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      scan_id TEXT,
      finding_id INTEGER,
      target_url TEXT,
      status TEXT DEFAULT 'launching' CHECK(status IN ('launching','active','paused','closed')),
      mode TEXT DEFAULT 'human' CHECK(mode IN ('human','ai','mixed')),
      current_url TEXT,
      proxy_host TEXT,
      proxy_port INTEGER,
      launched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      closed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
    );

    -- PenPard Browser action/event log (for future replay/PoC)
    CREATE TABLE IF NOT EXISTS browser_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      action_data TEXT,
      page_url TEXT,
      page_title TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      source TEXT DEFAULT 'human' CHECK(source IN ('human','ai','system')),
      FOREIGN KEY (session_id) REFERENCES browser_sessions(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_browser_sessions_user ON browser_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_browser_sessions_status ON browser_sessions(status);
    CREATE INDEX IF NOT EXISTS idx_browser_sessions_scan ON browser_sessions(scan_id);
    CREATE INDEX IF NOT EXISTS idx_browser_actions_session ON browser_actions(session_id);
  `);

  // Seed lock_key_hash if not exists (default key: "penpard")
  const lockKeyHash = bcrypt.hashSync('penpard', 12);
  db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES ('lock_key_hash', ?)`).run(lockKeyHash);

  // Seed operator user if not exists (for scans - user_id reference)
  const operatorExists = db.prepare('SELECT id FROM users WHERE username = ?').get('operator');
  const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');

  if (!operatorExists) {
    if (adminExists) {
      // Migrate existing admin to operator (keep id=1 for existing scans/whitelists)
      const passwordHash = bcrypt.hashSync('operator', 12);
      db.prepare(`
        UPDATE users SET username = 'operator', password_hash = ?, role = 'super_admin', credits = 999999, updated_at = CURRENT_TIMESTAMP
        WHERE username = 'admin'
      `).run(passwordHash);
      logger.info('Migrated admin user to operator (999999 credits)');
    } else {
      const passwordHash = bcrypt.hashSync('operator', 12);
      db.prepare(`
        INSERT INTO users (username, password_hash, role, credits)
        VALUES (?, ?, 'super_admin', 999999)
      `).run('operator', passwordHash);
      logger.info('Created default operator user (999999 credits)');
    }
  }

  // Migration: scans.initial_request (Send to PenPard raw request for continue-scan)
  const scanCols = db.prepare('PRAGMA table_info(scans)').all() as { name: string }[];
  if (!scanCols.some((c) => c.name === 'initial_request')) {
    db.exec('ALTER TABLE scans ADD COLUMN initial_request TEXT');
    logger.info('Added scans.initial_request column');
  }

  // Migration: source analysis columns
  if (!scanCols.some((c) => c.name === 'source_package_path')) {
    db.exec('ALTER TABLE scans ADD COLUMN source_package_path TEXT');
    logger.info('Added scans.source_package_path column');
  }
  if (!scanCols.some((c) => c.name === 'source_analysis_mode')) {
    db.exec('ALTER TABLE scans ADD COLUMN source_analysis_mode TEXT');
    logger.info('Added scans.source_analysis_mode column');
  }
  if (!scanCols.some((c) => c.name === 'source_analysis_result_json')) {
    db.exec('ALTER TABLE scans ADD COLUMN source_analysis_result_json TEXT');
    logger.info('Added scans.source_analysis_result_json column');
  }

  // Migration: browser_sessions.label (user-friendly session names for multi-session testing)
  const browserCols = db.prepare('PRAGMA table_info(browser_sessions)').all() as { name: string }[];
  if (!browserCols.some((c) => c.name === 'label')) {
    db.exec('ALTER TABLE browser_sessions ADD COLUMN label TEXT');
    logger.info('Added browser_sessions.label column');
  }

  logger.info('Database initialized successfully');
}

// Helper functions
export const findUserById = (id: number) => {
  return db.prepare('SELECT id, username, role, credits, created_at FROM users WHERE id = ?').get(id) as any;
};

export const updateUserCredits = (userId: number, credits: number) => {
  return db.prepare('UPDATE users SET credits = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(credits, userId);
};

export const getUserWhitelists = (userId: number) => {
  return db.prepare('SELECT * FROM whitelists WHERE user_id = ?').all(userId) as any[];
};

export const createScan = (data: {
  id: string; userId: number; type: string; target: string;
  sourcePackagePath?: string; sourceAnalysisMode?: string;
}) => {
  return db.prepare(`
    INSERT INTO scans (id, user_id, type, target, status, source_package_path, source_analysis_mode)
    VALUES (?, ?, ?, ?, 'queued', ?, ?)
  `).run(data.id, data.userId, data.type, data.target, data.sourcePackagePath ?? null, data.sourceAnalysisMode ?? null);
};

export const getScan = (id: string) => {
  return db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as any;
};

export const updateScanStatus = (id: string, status: string, errorMessage?: string) => {
  if (status === 'completed' || status === 'failed') {
    return db.prepare(`
      UPDATE scans SET status = ?, completed_at = CURRENT_TIMESTAMP, error_message = ?
      WHERE id = ?
    `).run(status, errorMessage || null, id);
  }
  return db.prepare('UPDATE scans SET status = ? WHERE id = ?').run(status, id);
};

export const setScanInitialRequest = (scanId: string, rawRequest: string | null) => {
  return db.prepare('UPDATE scans SET initial_request = ? WHERE id = ?').run(rawRequest ?? null, scanId);
};

export const saveSourceAnalysisResult = (scanId: string, resultJson: string) => {
  return db.prepare('UPDATE scans SET source_analysis_result_json = ? WHERE id = ?').run(resultJson, scanId);
};

export const getSourceAnalysisResult = (scanId: string): any | null => {
  const row = db.prepare('SELECT source_analysis_result_json FROM scans WHERE id = ?').get(scanId) as any;
  if (!row?.source_analysis_result_json) return null;
  try { return JSON.parse(row.source_analysis_result_json); } catch { return null; }
};

/** Permanently delete scans by id; only deletes rows where user_id matches (CASCADE removes related data). */
export const deleteScans = (scanIds: string[], userId: number) => {
  if (!scanIds.length) return { changes: 0 };
  const placeholders = scanIds.map(() => '?').join(',');
  return db.prepare(`DELETE FROM scans WHERE user_id = ? AND id IN (${placeholders})`).run(userId, ...scanIds);
};

export const getVulnerabilitiesByScan = (scanId: string) => {
  return db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId) as any[];
};

export const addVulnerability = (data: {
  scanId: string;
  name: string;
  description?: string;
  severity: string;
  cvssScore?: number;
  cvssVector?: string;
  cwe?: string;
  cve?: string;
  request?: string;
  response?: string;
  evidence?: string;
  remediation?: string;
  screenshotPath?: string;
}) => {
  // better-sqlite3 rejects undefined values — build explicit safe array
  const safeVal = (v: any, fallback: any = null) => (v === undefined || v === null) ? fallback : v;
  const values = [
    safeVal(data.scanId, 'unknown'),
    safeVal(data.name, 'Unknown Vulnerability'),
    safeVal(data.description),
    safeVal(data.severity, 'medium'),
    safeVal(data.cvssScore),
    safeVal(data.cvssVector),
    safeVal(data.cwe),
    safeVal(data.cve),
    safeVal(data.request),
    safeVal(data.response),
    safeVal(data.evidence),
    safeVal(data.remediation),
    safeVal(data.screenshotPath),
  ];
  return db.prepare(`
    INSERT INTO vulnerabilities (scan_id, name, description, severity, cvss_score, cvss_vector, cwe, cve, request, response, evidence, remediation, screenshot_path)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(...values);
};

// ── Scan Logs (persisted to DB) ──
// Lazy-initialized prepared statements (tables may not exist at module load time)

export const saveScanLogs = (scanId: string, logs: string[]) => {
  if (!logs || logs.length === 0) return;
  try {
    const stmt = db.prepare('INSERT INTO scan_logs (scan_id, message) VALUES (?, ?)');
    const insertMany = db.transaction((messages: string[]) => {
      for (const msg of messages) {
        stmt.run(scanId, msg);
      }
    });
    insertMany(logs);
  } catch (e: any) {
    logger.error(`Failed to save scan logs: ${e.message}`);
  }
};

export const getScanLogs = (scanId: string): string[] => {
  const rows = db.prepare('SELECT message FROM scan_logs WHERE scan_id = ? ORDER BY id ASC').all(scanId) as { message: string }[];
  return rows.map(r => r.message);
};

// ── Scan Chat Messages (persisted to DB) ──

export const saveChatMessage = (scanId: string, role: 'human' | 'assistant', content: string) => {
  try {
    db.prepare('INSERT INTO scan_chat_messages (scan_id, role, content) VALUES (?, ?, ?)').run(scanId, role, content);
  } catch (e: any) {
    logger.error(`Failed to save chat message: ${e.message}`);
  }
};

export const getChatMessages = (scanId: string): { role: string; content: string; created_at: string }[] => {
  return db.prepare('SELECT role, content, created_at FROM scan_chat_messages WHERE scan_id = ? ORDER BY id ASC').all(scanId) as any[];
};

// ── Report Analysis (Red Team Mind Reconstruction) ──

export const createAnalysis = (data: { id: string; userId: number; filename: string; filePath: string }) => {
  return db.prepare(`
    INSERT INTO report_analyses (id, user_id, filename, file_path, status)
    VALUES (?, ?, ?, ?, 'pending')
  `).run(data.id, data.userId, data.filename, data.filePath);
};

export const getAnalysis = (id: string) => {
  return db.prepare('SELECT * FROM report_analyses WHERE id = ?').get(id) as any;
};

export const getUserAnalyses = (userId: number) => {
  return db.prepare('SELECT * FROM report_analyses WHERE user_id = ? ORDER BY created_at DESC').all(userId) as any[];
};

export const updateAnalysisStatus = (id: string, status: string, errorMessage?: string) => {
  if (status === 'completed' || status === 'failed') {
    return db.prepare(`
      UPDATE report_analyses SET status = ?, completed_at = CURRENT_TIMESTAMP, error_message = ?
      WHERE id = ?
    `).run(status, errorMessage || null, id);
  }
  return db.prepare('UPDATE report_analyses SET status = ? WHERE id = ?').run(status, id);
};

export const updateAnalysisMetadata = (id: string, metadataJson: string) => {
  return db.prepare('UPDATE report_analyses SET report_metadata_json = ? WHERE id = ?').run(metadataJson, id);
};

export const updateAnalysisBehavioralProfile = (id: string, profileJson: string) => {
  return db.prepare('UPDATE report_analyses SET behavioral_profile_json = ? WHERE id = ?').run(profileJson, id);
};

export const addAnalysisFinding = (data: {
  analysisId: string;
  title: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  description?: string;
  pocStepsJson?: string;
  rawHttpRequestsJson?: string;
  payloadsJson?: string;
  evidenceJson?: string;
  recommendation?: string;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  return db.prepare(`
    INSERT INTO analysis_findings (analysis_id, title, severity, cvss_score, cvss_vector, description, poc_steps_json, raw_http_requests_json, payloads_json, evidence_json, recommendation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    data.analysisId, data.title, safeVal(data.severity), safeVal(data.cvssScore), safeVal(data.cvssVector),
    safeVal(data.description), safeVal(data.pocStepsJson), safeVal(data.rawHttpRequestsJson),
    safeVal(data.payloadsJson), safeVal(data.evidenceJson), safeVal(data.recommendation)
  );
};

export const getAnalysisFindings = (analysisId: string) => {
  return db.prepare('SELECT * FROM analysis_findings WHERE analysis_id = ? ORDER BY id ASC').all(analysisId) as any[];
};

export const updateAnalysisFinding = (findingId: number, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE analysis_findings SET ${setClauses} WHERE id = ?`).run(...values, findingId);
};

export const saveAnalysisLog = (analysisId: string, message: string) => {
  try {
    db.prepare('INSERT INTO analysis_logs (analysis_id, message) VALUES (?, ?)').run(analysisId, message);
  } catch (e: any) {
    logger.error(`Failed to save analysis log: ${e.message}`);
  }
};

export const getAnalysisLogs = (analysisId: string): string[] => {
  const rows = db.prepare('SELECT message FROM analysis_logs WHERE analysis_id = ? ORDER BY id ASC').all(analysisId) as { message: string }[];
  return rows.map(r => r.message);
};

export const deleteAnalysis = (analysisId: string, userId: number) => {
  return db.prepare('DELETE FROM report_analyses WHERE id = ? AND user_id = ?').run(analysisId, userId);
};

// ── Mindset TTP Library ──

export const addTTP = (data: {
  id: string;
  sourceAnalysisId: string;
  sourceFindingId?: number;
  title: string;
  vulnerabilityClass: string;
  discoveryStrategyJson?: string;
  preconditionsJson?: string;
  entrypointHintsJson?: string;
  requestTemplatesJson?: string;
  payloadTemplatesJson?: string;
  verificationCriteriaJson?: string;
  confidence?: number;
  generalizationNotes?: string;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  return db.prepare(`
    INSERT INTO mindset_ttps (id, source_analysis_id, source_finding_id, title, vulnerability_class, discovery_strategy_json, preconditions_json, entrypoint_hints_json, request_templates_json, payload_templates_json, verification_criteria_json, confidence, generalization_notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    data.id, data.sourceAnalysisId, safeVal(data.sourceFindingId), data.title, data.vulnerabilityClass,
    safeVal(data.discoveryStrategyJson), safeVal(data.preconditionsJson), safeVal(data.entrypointHintsJson),
    safeVal(data.requestTemplatesJson), safeVal(data.payloadTemplatesJson), safeVal(data.verificationCriteriaJson),
    data.confidence ?? 0.5, safeVal(data.generalizationNotes)
  );
};

export const getAllTTPs = () => {
  return db.prepare('SELECT * FROM mindset_ttps ORDER BY created_at DESC').all() as any[];
};

export const getActiveTTPs = () => {
  return db.prepare('SELECT * FROM mindset_ttps WHERE is_active = 1 ORDER BY confidence DESC').all() as any[];
};

export const getTTPById = (id: string) => {
  return db.prepare('SELECT * FROM mindset_ttps WHERE id = ?').get(id) as any;
};

export const getTTPsByAnalysis = (analysisId: string) => {
  return db.prepare('SELECT * FROM mindset_ttps WHERE source_analysis_id = ? ORDER BY created_at ASC').all(analysisId) as any[];
};

export const toggleTTPActive = (id: string, isActive: boolean) => {
  return db.prepare('UPDATE mindset_ttps SET is_active = ? WHERE id = ?').run(isActive ? 1 : 0, id);
};

export const getMindsetProfile = () => {
  return db.prepare('SELECT * FROM mindset_profile ORDER BY updated_at DESC LIMIT 1').get() as any;
};

export const upsertMindsetProfile = (profileJson: string) => {
  const existing = getMindsetProfile();
  if (existing) {
    return db.prepare('UPDATE mindset_profile SET profile_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(profileJson, existing.id);
  }
  return db.prepare('INSERT INTO mindset_profile (profile_json) VALUES (?)').run(profileJson);
};

// ── Presence Scan Helpers ──

export const createPresenceScanRun = (data: {
  id: string; userId: number; ttpId: string; ttpTitle?: string; targetsCount: number;
}) => {
  return db.prepare(`
    INSERT INTO presence_scan_runs (id, user_id, ttp_id, ttp_title, targets_count, status, started_at)
    VALUES (?, ?, ?, ?, ?, 'running', CURRENT_TIMESTAMP)
  `).run(data.id, data.userId, data.ttpId, data.ttpTitle || null, data.targetsCount);
};

export const getPresenceScanRun = (id: string) => {
  return db.prepare('SELECT * FROM presence_scan_runs WHERE id = ?').get(id) as any;
};

export const getUserPresenceScanRuns = (userId: number) => {
  return db.prepare('SELECT * FROM presence_scan_runs WHERE user_id = ? ORDER BY created_at DESC').all(userId) as any[];
};

export const updatePresenceScanRun = (id: string, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE presence_scan_runs SET ${setClauses} WHERE id = ?`).run(...values, id);
};

export const addPresenceScanTarget = (data: {
  runId: string; targetRaw: string; targetUrl: string;
  targetHost?: string; targetPort?: number; targetScheme?: string;
}) => {
  return db.prepare(`
    INSERT INTO presence_scan_targets (run_id, target_raw, target_url, target_host, target_port, target_scheme)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(data.runId, data.targetRaw, data.targetUrl, data.targetHost || null, data.targetPort || null, data.targetScheme || null);
};

export const updatePresenceScanTarget = (id: number, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE presence_scan_targets SET ${setClauses} WHERE id = ?`).run(...values, id);
};

export const getPresenceScanTargets = (runId: string, verdict?: string) => {
  if (verdict) {
    return db.prepare('SELECT * FROM presence_scan_targets WHERE run_id = ? AND verdict = ? ORDER BY id ASC').all(runId, verdict) as any[];
  }
  return db.prepare('SELECT * FROM presence_scan_targets WHERE run_id = ? ORDER BY id ASC').all(runId) as any[];
};

export const addPresenceScanLog = (runId: string, message: string) => {
  try {
    db.prepare('INSERT INTO presence_scan_logs (run_id, message) VALUES (?, ?)').run(runId, message);
  } catch (e: any) {
    logger.error(`Failed to save presence scan log: ${e.message}`);
  }
};

export const getPresenceScanLogs = (runId: string): string[] => {
  const rows = db.prepare('SELECT message FROM presence_scan_logs WHERE run_id = ? ORDER BY id ASC').all(runId) as { message: string }[];
  return rows.map(r => r.message);
};

export const deletePresenceScanRun = (id: string, userId: number) => {
  return db.prepare('DELETE FROM presence_scan_runs WHERE id = ? AND user_id = ?').run(id, userId);
};

export const addPresenceScanRunTTP = (runId: string, ttpId: string, ttpTitle?: string) => {
  return db.prepare('INSERT OR IGNORE INTO presence_scan_run_ttps (run_id, ttp_id, ttp_title) VALUES (?, ?, ?)').run(runId, ttpId, ttpTitle || null);
};

export const getPresenceScanRunTTPs = (runId: string): { ttp_id: string; ttp_title: string | null }[] => {
  return db.prepare('SELECT ttp_id, ttp_title FROM presence_scan_run_ttps WHERE run_id = ? ORDER BY id ASC').all(runId) as any[];
};

// ── TTP Test Playbook Cache ──

export const getCachedPlaybook = (ttpId: string): { content: string; model: string; tokens: number; created_at: string } | undefined => {
  return db.prepare('SELECT content, model, tokens, created_at FROM ttp_test_playbooks WHERE ttp_id = ? ORDER BY created_at DESC LIMIT 1').get(ttpId) as any;
};

export const cachePlaybook = (ttpId: string, content: string, model: string, tokens: number) => {
  db.prepare('INSERT INTO ttp_test_playbooks (ttp_id, content, model, tokens) VALUES (?, ?, ?, ?)').run(ttpId, content, model, tokens);
};

// ── PenPard Browser Session Helpers ──

export const createBrowserSession = (data: {
  id: string; userId: number; scanId?: string; findingId?: number;
  targetUrl?: string; proxyHost?: string; proxyPort?: number;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  return db.prepare(`
    INSERT INTO browser_sessions (id, user_id, scan_id, finding_id, target_url, status, mode, current_url, proxy_host, proxy_port)
    VALUES (?, ?, ?, ?, ?, 'launching', 'human', ?, ?, ?)
  `).run(
    data.id, data.userId, safeVal(data.scanId), safeVal(data.findingId),
    safeVal(data.targetUrl), safeVal(data.targetUrl),
    safeVal(data.proxyHost), safeVal(data.proxyPort)
  );
};

export const getBrowserSession = (id: string) => {
  return db.prepare('SELECT * FROM browser_sessions WHERE id = ?').get(id) as any;
};

export const getUserBrowserSessions = (userId: number) => {
  return db.prepare('SELECT * FROM browser_sessions WHERE user_id = ? ORDER BY launched_at DESC').all(userId) as any[];
};

export const updateBrowserSession = (id: string, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE browser_sessions SET ${setClauses} WHERE id = ?`).run(...values, id);
};

export const closeBrowserSession = (sessionId: string) => {
  return db.prepare(`
    UPDATE browser_sessions SET status = 'closed', closed_at = CURRENT_TIMESTAMP WHERE id = ? AND status != 'closed'
  `).run(sessionId);
};

export const addBrowserAction = (data: {
  sessionId: string; actionType: string; actionData?: string;
  pageUrl?: string; pageTitle?: string; source?: string;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  try {
    return db.prepare(`
      INSERT INTO browser_actions (session_id, action_type, action_data, page_url, page_title, source)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      data.sessionId, data.actionType, safeVal(data.actionData),
      safeVal(data.pageUrl), safeVal(data.pageTitle), data.source || 'human'
    );
  } catch (e: any) {
    logger.error(`Failed to save browser action: ${e.message}`);
  }
};

export const getBrowserActions = (sessionId: string) => {
  return db.prepare('SELECT * FROM browser_actions WHERE session_id = ? ORDER BY id ASC').all(sessionId) as any[];
};

export const deleteClosedBrowserSessions = (userId: number) => {
  // browser_actions has ON DELETE CASCADE, so deleting sessions auto-deletes their actions
  const result = db.prepare('DELETE FROM browser_sessions WHERE user_id = ? AND status = ?').run(userId, 'closed');
  return result.changes;
};

// ── Schema Validation ──

/** All tables that must exist for the backend to function correctly. */
const REQUIRED_TABLES = [
  'users', 'whitelists', 'llm_config', 'mcp_servers', 'settings',
  'scans', 'vulnerabilities', 'reports', 'token_usage', 'scan_logs',
  'scan_chat_messages', 'report_analyses', 'analysis_findings', 'analysis_logs',
  'mindset_ttps', 'mindset_profile', 'ttp_test_playbooks',
  'presence_scan_runs', 'presence_scan_targets', 'presence_scan_logs', 'presence_scan_run_ttps',
  'browser_sessions', 'browser_actions',
];

/**
 * Validates that the database schema contains all required tables.
 * Throws an error with a clear message listing missing tables if the schema is incomplete.
 */
export function validateSchema(database?: DatabaseType): void {
  const targetDb = database || db;
  const existing = targetDb
    .prepare("SELECT name FROM sqlite_master WHERE type='table'")
    .all() as { name: string }[];
  const existingNames = new Set(existing.map(r => r.name));
  const missing = REQUIRED_TABLES.filter(t => !existingNames.has(t));

  if (missing.length > 0) {
    throw new Error(
      `DATABASE SCHEMA INCOMPLETE — missing ${missing.length} required table(s): ${missing.join(', ')}. ` +
      `Run the backend normally to auto-create all tables, or delete the DB file and restart. ` +
      `Do NOT use the CLI --recreate_db_danger command with an outdated CLI version.`
    );
  }
}

/**
 * Marks scans stuck in non-terminal states as 'interrupted' after a backend restart.
 * Called once during startup to clean up orphaned scan records.
 */
export function recoverOrphanedScans(): number {
  const nonTerminalStatuses = ['queued', 'initializing', 'testing', 'reporting', 'auditing', 'crawling', 'analyzing', 'paused'];
  const placeholders = nonTerminalStatuses.map(() => '?').join(',');
  const result = db.prepare(`
    UPDATE scans SET status = 'interrupted', error_message = 'Backend restarted while scan was in progress. Scan state was lost.', completed_at = CURRENT_TIMESTAMP
    WHERE status IN (${placeholders})
  `).run(...nonTerminalStatuses);
  return result.changes;
}
