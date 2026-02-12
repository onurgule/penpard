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

export const createScan = (data: { id: string; userId: number; type: string; target: string }) => {
  return db.prepare(`
    INSERT INTO scans (id, user_id, type, target, status)
    VALUES (?, ?, ?, ?, 'queued')
  `).run(data.id, data.userId, data.type, data.target);
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

const insertLogStmt = db.prepare('INSERT INTO scan_logs (scan_id, message) VALUES (?, ?)');
const insertLogsTransaction = db.transaction((scanId: string, messages: string[]) => {
  for (const msg of messages) {
    insertLogStmt.run(scanId, msg);
  }
});

export const saveScanLogs = (scanId: string, logs: string[]) => {
  if (!logs || logs.length === 0) return;
  try {
    insertLogsTransaction(scanId, logs);
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
