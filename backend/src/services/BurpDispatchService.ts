import { BurpMCPClient } from './burp-mcp';
import { PreparedBurpDispatchRequest, prepareBurpDispatchRequest } from './burp-request';

type BurpDispatchTarget = 'repeater' | 'intruder' | 'scanner';

export interface BurpDispatchInput {
    rawRequest?: string;
    vulnName?: string;
    url?: string;
    method?: string;
    headers?: Record<string, any>;
    body?: string;
    target?: string;
}

export interface BurpDispatchResult {
    success: true;
    target: BurpDispatchTarget;
    prepared: PreparedBurpDispatchRequest;
    message: string;
}

function normalizeTarget(target: string | undefined): BurpDispatchTarget {
    if (target === 'intruder' || target === 'scanner') {
        return target;
    }
    return 'repeater';
}

export class BurpDispatchService {
    public async dispatch(input: BurpDispatchInput): Promise<BurpDispatchResult> {
        const dispatchTarget = normalizeTarget(input.target);
        if (!input.rawRequest && !input.url) {
            throw new Error('rawRequest or url is required');
        }

        const burp = new BurpMCPClient();
        const available = await burp.isAvailable();
        if (!available) {
            throw new Error('Burp Suite is not connected');
        }

        const prepared = prepareBurpDispatchRequest({
            rawRequest: input.rawRequest,
            url: typeof input.url === 'string' ? input.url : undefined,
            method: typeof input.method === 'string' ? input.method : undefined,
            headers: input.headers && typeof input.headers === 'object' ? input.headers : undefined,
            body: typeof input.body === 'string' ? input.body : undefined,
        });

        if (!prepared) {
            throw new Error('Could not normalize the request for Burp. Ensure a valid raw request or target URL is present.');
        }

        const targetLabels: Record<BurpDispatchTarget, string> = {
            repeater: 'Repeater',
            intruder: 'Intruder',
            scanner: 'Active Scan',
        };

        if (dispatchTarget === 'repeater') {
            await burp.callTool('send_to_repeater', {
                host: prepared.host,
                port: prepared.port,
                useHttps: prepared.useHttps,
                request: prepared.request,
                name: input.vulnName || 'PenPard Finding',
            });
        } else if (dispatchTarget === 'intruder') {
            await burp.callTool('send_to_intruder', {
                host: prepared.host,
                port: prepared.port,
                useHttps: prepared.useHttps,
                request: prepared.request,
            });
        } else {
            await burp.callTool('send_to_scanner', {
                host: prepared.host,
                port: prepared.port,
                useHttps: prepared.useHttps,
                request: prepared.request,
                url: prepared.fullUrl,
            });
        }

        return {
            success: true,
            target: dispatchTarget,
            prepared,
            message: `Sent to Burp ${targetLabels[dispatchTarget]}: ${prepared.host}`,
        };
    }
}

export const burpDispatchService = new BurpDispatchService();
