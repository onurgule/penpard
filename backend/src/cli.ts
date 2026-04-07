#!/usr/bin/env node
/**
 * PenPard CLI Tool
 * Cross-platform database and user management utility
 * 
 * Uses the same authoritative schema from db/init.ts as the backend server.
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

import bcrypt from 'bcryptjs';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { spawn, execSync } from 'child_process';

// Import the authoritative database instance and initialization from the backend
import { db, initDatabase, validateSchema } from './db/init';

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

// Get database path - same logic as db/init.ts and Electron app
function getDbPath(): string {
    if (process.env.DATABASE_PATH) {
        return process.env.DATABASE_PATH;
    }

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

// Commands
async function restartDb(): Promise<void> {
    log('\n🔄 Restarting database...', colors.bright);

    try {
        // Ensure schema is up to date first
        await initDatabase();

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
            DELETE FROM token_usage;
            DELETE FROM scan_logs;
            DELETE FROM scan_chat_messages;
            DELETE FROM report_analyses;
            DELETE FROM analysis_findings;
            DELETE FROM analysis_logs;
            DELETE FROM mindset_ttps;
            DELETE FROM mindset_profile;
            DELETE FROM ttp_test_playbooks;
            DELETE FROM presence_scan_runs;
            DELETE FROM presence_scan_targets;
            DELETE FROM presence_scan_logs;
            DELETE FROM presence_scan_run_ttps;
            DELETE FROM browser_sessions;
            DELETE FROM browser_actions;
        `);

        // Recreate default admin
        const passwordHash = await bcrypt.hash('securepass', 12);
        db.prepare(`
            INSERT INTO users (username, password_hash, role, credits)
            VALUES (?, ?, 'super_admin', 100)
        `).run('admin', passwordHash);

        logSuccess('Database cleared and reset (all 23 tables)');
        logSuccess('Default admin user created (admin/securepass)');

    } catch (e: any) {
        logError(`Failed to restart database: ${e.message}`);
        process.exit(1);
    }
}

async function createUser(username: string, password: string, role = 'user'): Promise<void> {
    log(`\n👤 Creating user: ${username}`, colors.bright);

    if (!['super_admin', 'admin', 'user'].includes(role)) {
        logError(`Invalid role: ${role}. Must be one of: super_admin, admin, user`);
        process.exit(1);
    }

    await initDatabase();

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

    } catch (e: any) {
        logError(`Failed to create user: ${e.message}`);
        process.exit(1);
    }
}

async function recreateDbDanger(): Promise<void> {
    log('\n⚠️  WARNING: This will DELETE ALL DATA!', colors.red);
    log('   This action cannot be undone.\n', colors.red);

    const dbPath = getDbPath();

    // Check if database exists
    if (fs.existsSync(dbPath)) {
        // Close the imported db connection before deleting the file
        try { db.close(); } catch { /* may already be closed */ }

        fs.unlinkSync(dbPath);
        logWarning(`Deleted: ${dbPath}`);

        // Also delete WAL files if they exist
        const walPath = dbPath + '-wal';
        const shmPath = dbPath + '-shm';
        if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
        if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    }

    // Recreate using the authoritative schema from db/init.ts
    // We need a fresh import since we closed the old connection
    // The simplest approach: use the same Database constructor and initDatabase logic
    const Database = (await import('better-sqlite3')).default;
    const freshDb = new Database(dbPath);
    freshDb.pragma('journal_mode = WAL');

    // We can't easily re-run initDatabase() since db is a module-level singleton.
    // Instead, just start a fresh backend process or inform the user.
    // For now, exec the schema creation by importing the module fresh.
    freshDb.close();

    logWarning('Database file deleted. Starting fresh initialization...');

    // Re-import to get a fresh db connection and run full schema
    // Since ESM/CJS caching may prevent re-import, use execSync to run init
    try {
        execSync('node -e "require(\'./db/init\').initDatabase().then(() => process.exit(0))"', {
            cwd: path.join(__dirname),
            stdio: 'inherit',
            timeout: 15000,
        });
    } catch {
        // Fallback: just create the file, and let the backend create schema on next start
        logWarning('Could not auto-initialize schema. The backend will create it on next startup.');
        const fallbackDb = new Database(dbPath);
        fallbackDb.pragma('journal_mode = WAL');
        fallbackDb.close();
    }

    logSuccess('Database recreated. Start the backend to complete schema initialization.');
    logInfo('Run: penpard --start_backend');
}

function listUsers(): void {
    log('\n👥 Users:', colors.bright);

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

    } catch (e: any) {
        logError(`Failed to list users: ${e.message}`);
        process.exit(1);
    }
}

function deleteUser(username: string): void {
    log(`\n🗑️  Deleting user: ${username}`, colors.bright);

    if (username === 'admin') {
        logError("Cannot delete the default 'admin' user");
        process.exit(1);
    }

    try {
        const result = db.prepare('DELETE FROM users WHERE username = ?').run(username);

        if (result.changes === 0) {
            logError(`User '${username}' not found`);
            process.exit(1);
        }

        logSuccess(`User '${username}' deleted`);

    } catch (e: any) {
        logError(`Failed to delete user: ${e.message}`);
        process.exit(1);
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
