import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { extractRoutesWithAI } from '../src/services/source-analysis/utils/ai-route-extractor';
import { llmRuntime } from '../src/services/llm/LlmRuntime';
import { logger } from '../src/utils/logger';

test('AI route extractor passes user scope to the runtime and avoids logging raw LLM output on parse failures', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'penpard-ai-routes-'));
    const routeFile = path.join(tempDir, 'routes.ts');
    fs.writeFileSync(
        routeFile,
        `
        import express from 'express';
        const app = express();
        app.use('/api', router);
        `,
        'utf8',
    );

    const originalGenerate = llmRuntime.generate.bind(llmRuntime);
    const originalWarn = logger.warn.bind(logger);
    let capturedUserId: number | undefined;
    const warnCalls: Array<{ message: string; meta: any }> = [];

    (llmRuntime as any).generate = async (_request: any, options: any) => {
        capturedUserId = options?.userId;
        return {
            text: 'not-json secret-token https://10.0.0.9/internal',
        };
    };
    (logger as any).warn = (message: string, meta: any) => {
        warnCalls.push({ message, meta });
    };

    try {
        const routes = await extractRoutesWithAI(tempDir, [], 91);
        assert.deepEqual(routes, []);
        assert.equal(capturedUserId, 91);

        const parseWarning = warnCalls.find((entry) => entry.message.includes('Failed to parse LLM response as JSON'));
        assert.ok(parseWarning);
        assert.equal(typeof parseWarning?.meta.responseLength, 'number');
        assert.equal('raw' in (parseWarning?.meta || {}), false);
        assert.equal('responsePreview' in (parseWarning?.meta || {}), false);
    } finally {
        (llmRuntime as any).generate = originalGenerate;
        (logger as any).warn = originalWarn;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
