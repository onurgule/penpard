import { OpenAI } from 'openai';

export interface LocalAzureTestSupportConfig {
    endpoint: string;
    apiKey: string;
    model: string;
    apiVersion: string;
}

function clean(value: string | undefined): string {
    return (value || '').trim();
}

export function loadLocalAzureTestSupportConfig(env: NodeJS.ProcessEnv = process.env): LocalAzureTestSupportConfig | null {
    const endpoint = clean(env.AZURE_OPENAI_ENDPOINT);
    const apiKey = clean(env.AZURE_OPENAI_API_KEY);
    const model = clean(env.AZURE_OPENAI_MODEL);
    const apiVersion = clean(env.AZURE_OPENAI_API_VERSION) || '2025-01-01-preview';

    if (!endpoint || !apiKey || !model) {
        return null;
    }

    return {
        endpoint,
        apiKey,
        model,
        apiVersion,
    };
}

export function createLocalAzureTestSupportClient(env: NodeJS.ProcessEnv = process.env): { client: OpenAI; model: string } | null {
    const config = loadLocalAzureTestSupportConfig(env);
    if (!config) {
        return null;
    }

    const normalizedEndpoint = config.endpoint.replace(/\/$/, '');
    return {
        client: new OpenAI({
            apiKey: config.apiKey,
            baseURL: `${normalizedEndpoint}/openai/deployments/${config.model}`,
            defaultQuery: { 'api-version': config.apiVersion },
            defaultHeaders: { 'api-key': config.apiKey },
        }),
        model: config.model,
    };
}
