import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

function getDefaultDataDir(): string {
    if (process.platform === 'win32') {
        return path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'penpard', 'data');
    }
    if (process.platform === 'darwin') {
        return path.join(os.homedir(), 'Library', 'Application Support', 'penpard', 'data');
    }
    return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'penpard', 'data');
}

function resolveJwtSecret(): string {
    if (process.env.JWT_SECRET && process.env.JWT_SECRET !== 'change-this-to-a-random-secret-key') {
        return process.env.JWT_SECRET;
    }

    const configuredPath = process.env.JWT_SECRET_PATH;
    const derivedPath = process.env.DATABASE_PATH
        ? path.join(path.dirname(process.env.DATABASE_PATH), 'jwt-secret')
        : path.join(getDefaultDataDir(), 'jwt-secret');
    const secretPath = configuredPath || derivedPath;

    try {
        if (fs.existsSync(secretPath)) {
            const persistedSecret = fs.readFileSync(secretPath, 'utf8').trim();
            if (persistedSecret) {
                return persistedSecret;
            }
        }
    } catch {
        // Fall through to an ephemeral secret only if the persisted secret cannot be read.
    }

    return crypto.randomBytes(64).toString('hex');
}

function deriveEncryptionKey(): Buffer {
    return crypto.scryptSync(resolveJwtSecret(), 'penpard-integration-salt', 32);
}

export function encryptSecret(plaintext: string): { encrypted: string; iv: string } {
    const key = deriveEncryptionKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
        encrypted: Buffer.concat([encrypted, tag]).toString('base64'),
        iv: iv.toString('base64'),
    };
}

export function decryptSecret(encryptedB64: string, ivB64: string): string {
    const key = deriveEncryptionKey();
    const iv = Buffer.from(ivB64, 'base64');
    const data = Buffer.from(encryptedB64, 'base64');
    const tag = data.subarray(data.length - 16);
    const ciphertext = data.subarray(0, data.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
}
