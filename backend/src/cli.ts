#!/usr/bin/env node
/**
 * PenPard CLI Tool
 * Cross-platform database and user management utility
 * 
 * Usage:
 *   penpard --restart_db              Reset database to initial state (keeps tables)
 *   penpard --createuser <user> <pass> [role]  Create a new user
 *   penpard --recreate_db_danger      Delete and recreate entire database
 *   penpard --list_users              List all users
 *   penpard --delete_user <username>  Delete a user
 *   penpard --version                 Show version
 *   penpard --help                    Show this help
 */

import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { spawn, execSync } from 'child_process';

// ANSI Colors
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
};

function log(msg: string, color = colors.reset) {
    console.log(`${color}${msg}${colors.reset}`);
}

function logSuccess(msg: string) {
    log(`✓ ${msg}`, colors.green);
}

function logError(msg: string) {
    log(`✗ ${msg}`, colors.red);
}

function logWarning(msg: string) {
    log(`⚠ ${msg}`, colors.yellow);
}

function logInfo(msg: string) {
    log(`ℹ ${msg}`, colors.cyan);
}

// Get database path - same logic as Electron app
function getDbPath(): string {
    // Check environment variable first
    if (process.env.DATABASE_PATH) {
        return process.env.DATABASE_PATH;
    }

    // Default to AppData/Roaming on Windows, ~/.config on Linux/Mac
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

function ensureDbDirectory(dbPath: string): void {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

function getDatabase(): Database.Database {
    const dbPath = getDbPath();
    ensureDbDirectory(dbPath);

    logInfo(`Database path: ${dbPath}`);

    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    return db;
}

// Initialize database schema
function initSchema(db: Database.Database): void {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('super_admin', 'admin', 'user')),
            credits INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS whitelists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain_pattern TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS llm_config (
            provider TEXT PRIMARY KEY,
            api_key TEXT,
            model TEXT,
            is_active INTEGER DEFAULT 0,
            is_online INTEGER DEFAULT 0,
            settings_json TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

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

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('web', 'mobile')),
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            burp_scan_id TEXT,
            mobsf_hash TEXT,
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

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            file_path TEXT NOT NULL,
            format TEXT DEFAULT 'markdown',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_whitelists_user_id ON whitelists(user_id);
    `);
}

// Commands
async function restartDb(): Promise<void> {
    log('\n🔄 Restarting database...', colors.bright);

    const db = getDatabase();

    try {
        // Clear all data but keep schema
        db.exec(`
            DELETE FROM vulnerabilities;
            DELETE FROM reports;
            DELETE FROM scans;
            DELETE FROM whitelists;
            DELETE FROM mcp_servers;
            DELETE FROM llm_config;
            DELETE FROM settings;
            DELETE FROM users;
        `);

        // Recreate default admin
        const passwordHash = await bcrypt.hash('securepass', 12);
        db.prepare(`
            INSERT INTO users (username, password_hash, role, credits)
            VALUES (?, ?, 'super_admin', 100)
        `).run('admin', passwordHash);

        logSuccess('Database cleared and reset');
        logSuccess('Default admin user created (admin/securepass)');

    } finally {
        db.close();
    }
}

async function createUser(username: string, password: string, role = 'user'): Promise<void> {
    log(`\n👤 Creating user: ${username}`, colors.bright);

    if (!['super_admin', 'admin', 'user'].includes(role)) {
        logError(`Invalid role: ${role}. Must be one of: super_admin, admin, user`);
        process.exit(1);
    }

    const db = getDatabase();
    initSchema(db);

    try {
        // Check if user exists
        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existing) {
            logError(`User '${username}' already exists`);
            process.exit(1);
        }

        const passwordHash = await bcrypt.hash(password, 12);
        db.prepare(`
            INSERT INTO users (username, password_hash, role, credits)
            VALUES (?, ?, ?, 100)
        `).run(username, passwordHash, role);

        logSuccess(`User '${username}' created with role '${role}'`);

    } finally {
        db.close();
    }
}

async function recreateDbDanger(): Promise<void> {
    log('\n⚠️  WARNING: This will DELETE ALL DATA!', colors.red);
    log('   This action cannot be undone.\n', colors.red);

    const dbPath = getDbPath();

    // Check if database exists
    if (fs.existsSync(dbPath)) {
        fs.unlinkSync(dbPath);
        logWarning(`Deleted: ${dbPath}`);

        // Also delete WAL files if they exist
        const walPath = dbPath + '-wal';
        const shmPath = dbPath + '-shm';
        if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
        if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    }

    // Create fresh database
    const db = getDatabase();
    initSchema(db);

    // Create default admin
    const passwordHash = await bcrypt.hash('securepass', 12);
    db.prepare(`
        INSERT INTO users (username, password_hash, role, credits)
        VALUES (?, ?, 'super_admin', 100)
    `).run('admin', passwordHash);

    db.close();

    logSuccess('Database recreated from scratch');
    logSuccess('Default admin user created (admin/securepass)');
}

function listUsers(): void {
    log('\n👥 Users:', colors.bright);

    const db = getDatabase();
    initSchema(db);

    try {
        const users = db.prepare(`
            SELECT id, username, role, credits, created_at 
            FROM users 
            ORDER BY id
        `).all() as any[];

        if (users.length === 0) {
            logWarning('No users found');
            return;
        }

        console.log('\n  ID | Username         | Role         | Credits | Created');
        console.log('  ---|------------------|--------------|---------|--------------------');

        for (const user of users) {
            const id = String(user.id).padStart(3);
            const username = user.username.padEnd(16);
            const role = user.role.padEnd(12);
            const credits = String(user.credits).padStart(7);
            const created = user.created_at?.split('T')[0] || 'N/A';
            console.log(`  ${id} | ${username} | ${role} | ${credits} | ${created}`);
        }
        console.log('');

    } finally {
        db.close();
    }
}

function deleteUser(username: string): void {
    log(`\n🗑️  Deleting user: ${username}`, colors.bright);

    if (username === 'admin') {
        logError("Cannot delete the default 'admin' user");
        process.exit(1);
    }

    const db = getDatabase();

    try {
        const result = db.prepare('DELETE FROM users WHERE username = ?').run(username);

        if (result.changes === 0) {
            logError(`User '${username}' not found`);
            process.exit(1);
        }

        logSuccess(`User '${username}' deleted`);

    } finally {
        db.close();
    }
}

function showHelp(): void {
    console.log(`
${colors.cyan}${colors.bright}PenPard CLI${colors.reset} - Database Management Tool

${colors.bright}USAGE:${colors.reset}
    penpard <command> [options]

${colors.bright}COMMANDS:${colors.reset}
    ${colors.green}--start${colors.reset}
        Start both backend and frontend
        
    ${colors.green}--start_backend${colors.reset}
        Start only the backend server
        
    ${colors.green}--start_frontend${colors.reset}
        Start only the frontend server
        
    ${colors.green}--stop${colors.reset}
        Stop both backend and frontend
        
    ${colors.green}--stop_backend${colors.reset}
        Stop only the backend server
        
    ${colors.green}--stop_frontend${colors.reset}
        Stop only the frontend server
        
    ${colors.green}--restart_backend${colors.reset}
        Restart the backend server
        
    ${colors.green}--restart_frontend${colors.reset}
        Restart the frontend server
        
    ${colors.green}--status${colors.reset}
        Show status of backend and frontend
        
    ${colors.green}--restart_db${colors.reset}
        Reset database to initial state (clears all data, keeps schema)
        
    ${colors.green}--createuser <username> <password> [role]${colors.reset}
        Create a new user. Role: super_admin, admin, or user (default: user)
        
    ${colors.green}--recreate_db_danger${colors.reset}
        Delete and recreate entire database (DESTRUCTIVE!)
        
    ${colors.green}--list_users${colors.reset}
        List all users in the database
        
    ${colors.green}--delete_user <username>${colors.reset}
        Delete a user by username
        
    ${colors.green}--version${colors.reset}
        Show version information
        
    ${colors.green}--help${colors.reset}
        Show this help message

${colors.bright}EXAMPLES:${colors.reset}
    penpard --start
    penpard --restart_backend
    penpard --createuser pentester mypassword admin
    penpard --status
`);
}

function showVersion(): void {
    const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf-8'));
    log(`\nPenPard CLI v${packageJson.version}`, colors.cyan);
}

// Process management functions
function getProjectRoot(): string {
    return path.join(__dirname, '../..');
}

function startBackend(): void {
    log('\n🚀 Starting backend...', colors.bright);

    const projectRoot = getProjectRoot();

    const child = spawn('npm', ['run', 'dev:backend'], {
        cwd: projectRoot,
        shell: true,
        detached: true,
        stdio: 'ignore'
    });

    child.unref();

    logSuccess('Backend started in background');
    logInfo('Run "penpard --status" to check status');
}

function startFrontend(): void {
    log('\n🚀 Starting frontend...', colors.bright);

    const projectRoot = getProjectRoot();

    const child = spawn('npm', ['run', 'dev:frontend'], {
        cwd: projectRoot,
        shell: true,
        detached: true,
        stdio: 'ignore'
    });

    child.unref();

    logSuccess('Frontend started in background');
    logInfo('Access at http://localhost:3000');
}

function startAll(): void {
    log('\n🚀 Starting PenPard...', colors.bright);

    const projectRoot = getProjectRoot();

    const child = spawn('npm', ['run', 'dev'], {
        cwd: projectRoot,
        shell: true,
        detached: true,
        stdio: 'ignore'
    });

    child.unref();

    logSuccess('Backend and frontend started');
    logInfo('Backend: http://localhost:4000');
    logInfo('Frontend: http://localhost:3000');
}

function stopProcesses(processName: string): void {
    log(`\n🛑 Stopping ${processName}...`, colors.bright);

    try {
        if (process.platform === 'win32') {
            // Windows: find and kill node processes on specific ports
            if (processName === 'backend' || processName === 'all') {
                try {
                    execSync('for /f "tokens=5" %a in (\'netstat -aon ^| findstr :4000\') do taskkill /F /PID %a', { shell: 'cmd.exe', stdio: 'ignore' });
                    logSuccess('Backend stopped (port 4000)');
                } catch {
                    logInfo('Backend was not running');
                }
            }
            if (processName === 'frontend' || processName === 'all') {
                try {
                    execSync('for /f "tokens=5" %a in (\'netstat -aon ^| findstr :3000\') do taskkill /F /PID %a', { shell: 'cmd.exe', stdio: 'ignore' });
                    logSuccess('Frontend stopped (port 3000)');
                } catch {
                    logInfo('Frontend was not running');
                }
            }
        } else {
            // Linux/Mac
            if (processName === 'backend' || processName === 'all') {
                try {
                    execSync('lsof -ti:4000 | xargs kill -9 2>/dev/null', { stdio: 'ignore' });
                    logSuccess('Backend stopped (port 4000)');
                } catch {
                    logInfo('Backend was not running');
                }
            }
            if (processName === 'frontend' || processName === 'all') {
                try {
                    execSync('lsof -ti:3000 | xargs kill -9 2>/dev/null', { stdio: 'ignore' });
                    logSuccess('Frontend stopped (port 3000)');
                } catch {
                    logInfo('Frontend was not running');
                }
            }
        }
    } catch (error: any) {
        logWarning(`Could not stop ${processName}: ${error.message}`);
    }
}

function checkStatus(): void {
    log('\n📊 PenPard Status', colors.bright);

    const checkPort = (port: number): boolean => {
        try {
            if (process.platform === 'win32') {
                const result = execSync(`netstat -an | findstr :${port}`, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] });
                return result.includes('LISTENING');
            } else {
                execSync(`lsof -i:${port}`, { stdio: 'ignore' });
                return true;
            }
        } catch {
            return false;
        }
    };

    const backendRunning = checkPort(4000);
    const frontendRunning = checkPort(3000);

    console.log('');
    console.log(`  Backend  (port 4000): ${backendRunning ? colors.green + '● Running' : colors.red + '○ Stopped'}${colors.reset}`);
    console.log(`  Frontend (port 3000): ${frontendRunning ? colors.green + '● Running' : colors.red + '○ Stopped'}${colors.reset}`);
    console.log('');

    const dbPath = getDbPath();
    const dbExists = fs.existsSync(dbPath);
    console.log(`  Database: ${dbExists ? colors.green + '● Exists' : colors.yellow + '○ Not found'}${colors.reset}`);
    console.log(`  Path: ${dbPath}`);
    console.log('');
}

// Main
async function main(): Promise<void> {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        showHelp();
        return;
    }

    const command = args[0];

    try {
        switch (command) {
            // Process management
            case '--start':
                startAll();
                break;

            case '--start_backend':
                startBackend();
                break;

            case '--start_frontend':
                startFrontend();
                break;

            case '--stop':
                stopProcesses('all');
                break;

            case '--stop_backend':
                stopProcesses('backend');
                break;

            case '--stop_frontend':
                stopProcesses('frontend');
                break;

            case '--restart_backend':
                stopProcesses('backend');
                setTimeout(() => startBackend(), 1000);
                break;

            case '--restart_frontend':
                stopProcesses('frontend');
                setTimeout(() => startFrontend(), 1000);
                break;

            case '--status':
                checkStatus();
                break;

            // Database commands
            case '--restart_db':
            case '-r':
                await restartDb();
                break;

            case '--createuser':
            case '-c':
                if (args.length < 3) {
                    logError('Usage: penpard --createuser <username> <password> [role]');
                    process.exit(1);
                }
                await createUser(args[1], args[2], args[3] || 'user');
                break;

            case '--recreate_db_danger':
                await recreateDbDanger();
                break;

            case '--list_users':
            case '-l':
                listUsers();
                break;

            case '--delete_user':
            case '-d':
                if (args.length < 2) {
                    logError('Usage: penpard --delete_user <username>');
                    process.exit(1);
                }
                deleteUser(args[1]);
                break;

            case '--version':
            case '-v':
                showVersion();
                break;

            case '--help':
            case '-h':
                showHelp();
                break;

            default:
                logError(`Unknown command: ${command}`);
                showHelp();
                process.exit(1);
        }
    } catch (error: any) {
        logError(`Error: ${error.message}`);
        process.exit(1);
    }
}

main();
