import test from 'node:test';
import assert from 'node:assert/strict';

import { ScanChatService, ScanChatServiceError } from '../src/services/ScanChatService';

const scan = {
    id: 'scan-chat-service-test',
    target: 'https://app.example.com',
    type: 'web',
    status: 'completed',
    created_at: '2026-04-10T00:00:00.000Z',
    completed_at: '2026-04-10T00:05:00.000Z',
};

test('scan chat service routes live commands to the active agent and only persists the human message', async () => {
    const persisted: Array<{ role: string; content: string }> = [];
    let handledCommand = '';

    const service = new ScanChatService({
        runtimeService: {
            getActiveAgent: () => ({
                handleUserCommand: async (command: string) => {
                    handledCommand = command;
                },
            } as any),
        } as any,
        generate: async () => {
            throw new Error('LLM should not be called for active agent chats');
        },
        persistChatMessage: (_scanId, role, content) => {
            persisted.push({ role, content });
        },
        loadFindings: () => [],
    });

    const result = await service.handleCommand(scan, 'Continue with the authenticated flow');

    assert.deepEqual(result, { message: 'Command sent to agent' });
    assert.equal(handledCommand, 'Continue with the authenticated flow');
    assert.deepEqual(persisted, [
        { role: 'human', content: 'Continue with the authenticated flow' },
    ]);
});

test('scan chat service routes commands through live runtime wrappers when present', async () => {
    const persisted: Array<{ role: string; content: string }> = [];
    let handledCommand = '';

    const service = new ScanChatService({
        runtimeService: {
            getActiveAgent: () => undefined,
            sendCommandToActiveRuntime: async (_scanId: string, command: string) => {
                handledCommand = command;
                return true;
            },
        } as any,
        generate: async () => {
            throw new Error('LLM should not be called for active runtime chats');
        },
        persistChatMessage: (_scanId, role, content) => {
            persisted.push({ role, content });
        },
        loadFindings: () => [],
    });

    const result = await service.handleCommand(scan, 'Stay on the checkout route and keep probing totals');

    assert.deepEqual(result, { message: 'Command sent to agent' });
    assert.equal(handledCommand, 'Stay on the checkout route and keep probing totals');
    assert.deepEqual(persisted, [
        { role: 'human', content: 'Stay on the checkout route and keep probing totals' },
    ]);
});

test('scan chat service answers completed-scan questions with scan-context LLM prompts and persists the reply', async () => {
    const persisted: Array<{ role: string; content: string }> = [];
    let capturedRequest: any = null;
    let capturedMetadata: any = null;

    const service = new ScanChatService({
        runtimeService: {
            getActiveAgent: () => undefined,
        } as any,
        generate: async (request, metadata) => {
            capturedRequest = request;
            capturedMetadata = metadata;
            return { text: 'There is one high-severity XSS finding.' };
        },
        persistChatMessage: (_scanId, role, content) => {
            persisted.push({ role, content });
        },
        loadFindings: () => [{
            severity: 'high',
            name: 'Cross-Site Scripting (XSS) - /search (q)',
            description: 'Reflected payloads render in HTML.',
        }],
    });

    const result = await service.handleCommand(scan, 'What did you find?');

    assert.deepEqual(result, {
        message: 'Response from LLM',
        response: 'There is one high-severity XSS finding.',
        scanStatus: 'completed',
        isLive: false,
    });
    assert.deepEqual(capturedMetadata, { scanId: 'scan-chat-service-test', context: 'scan-post-chat' });
    assert.match(String(capturedRequest?.systemPrompt || ''), /Target: https:\/\/app\.example\.com/);
    assert.match(String(capturedRequest?.systemPrompt || ''), /Cross-Site Scripting \(XSS\) - \/search \(q\)/);
    assert.equal(capturedRequest?.userPrompt, 'What did you find?');
    assert.deepEqual(persisted, [
        { role: 'human', content: 'What did you find?' },
        { role: 'assistant', content: 'There is one high-severity XSS finding.' },
    ]);
});

test('scan chat service wraps inactive-scan LLM failures with route-safe error details', async () => {
    const service = new ScanChatService({
        runtimeService: {
            getActiveAgent: () => undefined,
        } as any,
        generate: async () => {
            throw new Error('missing api key');
        },
        persistChatMessage: () => {},
        loadFindings: () => [],
    });

    await assert.rejects(
        () => service.handleCommand(scan, 'Summarize the scan'),
        (error: any) => {
            assert.ok(error instanceof ScanChatServiceError);
            assert.equal(error.statusCode, 500);
            assert.equal(error.message, 'LLM query failed. Please check your LLM configuration.');
            assert.equal(error.details, 'missing api key');
            return true;
        },
    );
});
