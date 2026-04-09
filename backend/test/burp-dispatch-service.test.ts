import test from 'node:test';
import assert from 'node:assert/strict';

const { BurpDispatchService } = require('../src/services/BurpDispatchService') as typeof import('../src/services/BurpDispatchService');
const { BurpMCPClient } = require('../src/services/burp-mcp') as typeof import('../src/services/burp-mcp');

test('burp dispatch service normalizes URL-only scanner requests through a single control-plane seam', async () => {
    const originalIsAvailable = BurpMCPClient.prototype.isAvailable;
    const originalCallTool = BurpMCPClient.prototype.callTool;
    const calls: Array<{ tool: string; args: any }> = [];

    BurpMCPClient.prototype.isAvailable = async () => true;
    BurpMCPClient.prototype.callTool = async function(tool: string, args: any) {
        calls.push({ tool, args });
        return {};
    };

    try {
        const service = new BurpDispatchService();
        const result = await service.dispatch({
            target: 'scanner',
            url: 'https://app.example.com/api/me?id=1',
        });

        assert.equal(result.target, 'scanner');
        assert.equal(calls.length, 1);
        assert.equal(calls[0].tool, 'send_to_scanner');
        assert.equal(calls[0].args.host, 'app.example.com');
        assert.equal(calls[0].args.url, 'https://app.example.com/api/me?id=1');
        assert.match(calls[0].args.request, /^GET \/api\/me\?id=1 HTTP\/1\.1\r\nHost: app\.example\.com\r\n\r\n$/);
    } finally {
        BurpMCPClient.prototype.isAvailable = originalIsAvailable;
        BurpMCPClient.prototype.callTool = originalCallTool;
    }
});
