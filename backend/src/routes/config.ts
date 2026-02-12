
import { Router, Response } from 'express';
import { AuthRequest, authenticateToken } from '../middleware/auth';
import { llmProvider, LLMConfig } from '../services/LLMProviderService';
import { mcpManager, McpServerConfig } from '../services/McpManagerService';
import { logger } from '../utils/logger';

const router = Router();

/**
 * --- LLM Configuration Endpoints ---
 */

// Get all LLM configs
router.get('/llm', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const configs = llmProvider.getAllConfigs();
        res.json({ configs });
    } catch (error: any) {
        logger.error('Failed to get LLM configs', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to fetch settings' });
    }
});

// Update or Add LLM config
router.post('/llm', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const config: LLMConfig = req.body;
        llmProvider.updateConfig(config);
        res.json({ message: 'Configuration saved' });
    } catch (error: any) {
        logger.error('Failed to save LLM config', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to save settings' });
    }
});

// Test connection
router.post('/llm/test', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { provider } = req.body;

        if (!provider) {
            res.status(400).json({ error: true, message: 'Provider is required', status: 'offline' });
            return;
        }

        const result = await llmProvider.checkConnection(provider);

        if (result.success) {
            res.json({ message: 'Connection successful', status: 'online' });
        } else {
            res.status(400).json({ error: true, message: result.error || 'Connection failed', status: 'offline' });
        }
    } catch (error: any) {
        logger.error('LLM Test Error', { error: error.message });
        res.status(500).json({ error: true, message: error.message, status: 'offline' });
    }
});


/**
 * --- MCP Manager Endpoints ---
 */

// List servers
router.get('/mcp', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const servers = mcpManager.getAllServers();
        res.json({ servers });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to list servers' });
    }
});

// Add/Update server
router.post('/mcp', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const config: McpServerConfig = req.body;
        mcpManager.upsertServer(config);

        // If enabling, try start
        if (config.is_enabled) {
            mcpManager.startServer(config.name).catch(e => logger.error(`Auto-start failed for ${config.name}`, e));
        }

        res.json({ message: 'Server saved' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// Server Actions (Start/Stop/Restart)
router.post('/mcp/:name/:action', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const { name, action } = req.params;

        switch (action) {
            case 'start':
                await mcpManager.startServer(name);
                break;
            case 'stop':
                mcpManager.stopServer(name);
                break;
            case 'restart':
                await mcpManager.restartServer(name);
                break;
            case 'delete':
                mcpManager.deleteServer(name);
                break;
            default:
                res.status(400).json({ error: true, message: 'Invalid action' });
                return;
        }

        res.json({ message: `Action ${action} executed for ${name}` });
    } catch (error: any) {
        logger.error(`MCP Action failed: ${error.message}`);
        res.status(500).json({ error: true, message: error.message });
    }
});

// Get Logs
router.get('/mcp/logs', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const logs = mcpManager.getLogs(200);
        res.json({ logs });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get logs' });
    }
});

/**
 * --- Prompt Library Endpoints ---
 */

import { promptLibrary } from '../services/PromptLibraryService';

// Get all library prompts (scan templates)
router.get('/prompt-library', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        // Auto-refresh if stale (non-blocking background fetch)
        promptLibrary.refreshIfStale();

        const prompts = promptLibrary.getScanTemplates();
        const activeId = promptLibrary.getActivePromptId();

        res.json({
            prompts,
            activePromptId: activeId,
            total: prompts.length
        });
    } catch (error: any) {
        logger.error('Failed to get prompt library', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to get prompt library' });
    }
});

// Force refresh prompts from penpard.com
router.post('/prompt-library/refresh', authenticateToken, async (req: AuthRequest, res: Response) => {
    try {
        const result = await promptLibrary.fetchFromRemote();
        res.json(result);
    } catch (error: any) {
        logger.error('Failed to refresh prompt library', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to refresh', success: false });
    }
});

// Set active scan prompt
router.post('/prompt-library/activate', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { promptId } = req.body;
        if (!promptId) {
            res.status(400).json({ error: true, message: 'promptId is required' });
            return;
        }

        // Verify prompt exists
        const prompts = promptLibrary.getAll();
        const found = prompts.find(p => p.id === promptId);
        if (!found) {
            res.status(404).json({ error: true, message: 'Prompt not found in library' });
            return;
        }

        promptLibrary.setActivePromptId(promptId);
        res.json({ message: `Active prompt set to: ${found.name}`, promptId });
    } catch (error: any) {
        logger.error('Failed to activate prompt', { error: error.message });
        res.status(500).json({ error: true, message: 'Failed to activate prompt' });
    }
});

// Get the currently active prompt's full details
router.get('/prompt-library/active', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const activeId = promptLibrary.getActivePromptId();
        const prompt = promptLibrary.getAll().find(p => p.id === activeId);

        if (prompt) {
            res.json({ prompt, isDefault: false });
        } else {
            const defaultPrompt = promptLibrary.getAll().find(p => p.is_default);
            res.json({ prompt: defaultPrompt || null, isDefault: true });
        }
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get active prompt' });
    }
});

/**
 * --- Prompts Configuration Endpoints ---
 */

import { db } from '../db/init';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

// Setup multer for logo uploads
const logoStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, '../../uploads/logos');
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, `company-logo${ext}`);
    }
});
const logoUpload = multer({ storage: logoStorage });

// Get prompts
router.get('/prompts', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('prompts') as any;
        if (row) {
            res.json({ prompts: JSON.parse(row.value) });
        } else {
            res.json({ prompts: [] });
        }
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get prompts' });
    }
});

// Save prompts
router.post('/prompts', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { prompts } = req.body;
        db.prepare(`
            INSERT OR REPLACE INTO settings (key, value)
            VALUES ('prompts', ?)
        `).run(JSON.stringify(prompts));
        res.json({ message: 'Prompts saved' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to save prompts' });
    }
});

// Get logo
router.get('/logo', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const logoDir = path.join(__dirname, '../../uploads/logos');
        const files = fs.existsSync(logoDir) ? fs.readdirSync(logoDir) : [];
        const logoFile = files.find(f => f.startsWith('company-logo'));

        if (logoFile) {
            res.json({ logoUrl: `/uploads/logos/${logoFile}` });
        } else {
            res.json({ logoUrl: null });
        }
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get logo' });
    }
});

// Upload logo
router.post('/logo', authenticateToken, logoUpload.single('logo'), (req: AuthRequest, res: Response) => {
    try {
        if (!req.file) {
            res.status(400).json({ error: true, message: 'No file uploaded' });
            return;
        }
        res.json({ message: 'Logo uploaded', logoUrl: `/uploads/logos/${req.file.filename}` });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to upload logo' });
    }
});


/**
 * --- MobSF Configuration Endpoints ---
 */

// Get MobSF Config
router.get('/mobsf', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('mobsf_config') as any;
        let config = {
            url: process.env.MOBSF_API_URL || 'http://host.docker.internal:8000',
            key: process.env.MOBSF_API_KEY || ''
        };

        if (row && row.value) {
            config = { ...config, ...JSON.parse(row.value) };
        }

        res.json({ config });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to get MobSF config' });
    }
});

// Save MobSF Config
router.post('/mobsf', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
        const { url, key } = req.body;
        db.prepare(`
            INSERT OR REPLACE INTO settings (key, value)
            VALUES ('mobsf_config', ?)
        `).run(JSON.stringify({ url, key }));
        res.json({ message: 'MobSF configuration saved' });
    } catch (error: any) {
        res.status(500).json({ error: true, message: 'Failed to save MobSF config' });
    }
});

export default router;
