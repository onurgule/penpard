import { Router, Response } from 'express';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { llmProvider } from '../services/LLMProviderService';
import { mcpManager } from '../services/McpManagerService';
import axios from 'axios';
import { exec } from 'child_process';
import util from 'util';

const execAsync = util.promisify(exec);
const router = Router();

router.get('/', authenticateToken, async (req: AuthRequest, res: Response) => {
    // 1. LLM Status
    let llmStatus = { provider: 'None', model: 'None', configured: false };
    try {
        const llmConfig = llmProvider.getActiveConfig();
        llmStatus = {
            provider: llmConfig.provider,
            model: llmConfig.model,
            configured: true
        };
    } catch (e) {
        // No active config
    }

    // 2. MCP Servers Status
    const mcpServers = mcpManager.getAllServers();
    const activeMcpCount = mcpServers.filter(s => s.status === 'running').length;
    const mcpStatus = {
        total: mcpServers.length,
        active: activeMcpCount,
        servers: mcpServers.map(s => ({ name: s.name, status: s.status }))
    };

    // 3. Burp Status — read config from DB, fallback to env, then default
    let burpStatus = 'offline';
    try {
        const { db } = require('../db/init');
        let burpUrl = process.env.BURP_MCP_URL || 'http://localhost:9876';

        const burpRow = db.prepare('SELECT value FROM settings WHERE key = ?').get('burp_config') as any;
        if (burpRow && burpRow.value) {
            const cfg = JSON.parse(burpRow.value);
            const protocol = cfg.useHttps ? 'https' : 'http';
            burpUrl = `${protocol}://${cfg.host}:${cfg.port}`;
        }

        const response = await axios.get(`${burpUrl}/health`, { 
            timeout: 2000,
            validateStatus: () => true 
        });
        if (response.status === 200 || response.status !== 404) {
            burpStatus = 'online';
        }
    } catch (e: any) {
        if (e.code === 'ECONNREFUSED' || e.code === 'ENOTFOUND') {
            burpStatus = 'offline';
        } else if (e.response) {
            burpStatus = 'online';
        }
    }

    // 4. Nuclei Status
    let nucleiStatus = 'unknown';
    try {
        const { stdout } = await execAsync('nuclei -version');
        const versionLine = stdout.trim().split('\n')[0];
        // extract version like "2.9.8"
        nucleiStatus = versionLine.replace('nuclei version', '').trim();
        if (!nucleiStatus) nucleiStatus = 'installed';
    } catch (e) {
        nucleiStatus = 'not found';
    }

    // 5. MobSF Status
    let mobsfStatus = 'offline';
    try {
        const row = require('../db/init').db.prepare('SELECT value FROM settings WHERE key = ?').get('mobsf_config') as any;
        // Use localhost for npm, host.docker.internal for Docker
        let mobsfUrl = process.env.MOBSF_API_URL || 'http://localhost:8000';
        let mobsfKey = process.env.MOBSF_API_KEY || '';

        if (row && row.value) {
            const config = JSON.parse(row.value);
            if (config.url) mobsfUrl = config.url;
            if (config.key) mobsfKey = config.key;
        }

        // Remove trailing slash if exists
        mobsfUrl = mobsfUrl.replace(/\/$/, '');

        // Check MobSF API (e.g. /api/v1/about/version which usually requires key, 
        // or just root/login page to see if it's up)
        // We'll try to reach the main page or a public endpoint if available, but MobSF API usually needs key.
        // Let's try basic connection to the root URL.
        await axios.get(mobsfUrl, { timeout: 2000, validateStatus: () => true });
        mobsfStatus = 'online';
    } catch (e: any) {
        if (e.response) mobsfStatus = 'online';
    }

    res.json({
        llm: llmStatus,
        mcp: mcpStatus,
        burp: burpStatus,
        nuclei: nucleiStatus,
        mobsf: mobsfStatus
    });
});

export default router;
