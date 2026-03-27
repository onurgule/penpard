import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import AdmZip from 'adm-zip';
import { logger } from './logger';

import os from 'os';

export function selectLocalDirectory(): Promise<string> {
    return new Promise((resolve, reject) => {
        const platform = os.platform();

        if (platform === 'darwin') {
            // macOS
            const appleScript = `set folderPath to POSIX path of (choose folder with prompt "Select Source Code Directory")\nreturn folderPath`;
            exec(`osascript -e '${appleScript}'`, (error, stdout, stderr) => {
                if (error) {
                    logger.error('macOS picker failed', { stderr: stderr || error.message });
                    reject(new Error(`Picker Error (macOS): User cancelled or failed.`));
                    return;
                }
                const cleanPath = stdout.trim();
                if (!cleanPath) return reject(new Error('No directory selected (Dialog cancelled)'));
                resolve(cleanPath);
            });
        } else if (platform === 'win32') {
            // Windows
            const vbsPath = path.join(os.tmpdir(), `picker_${Date.now()}.vbs`);
            const vbsCode = `
Set objShell = CreateObject("Shell.Application")
Set objFolder = objShell.BrowseForFolder(0, "Select Source Code Directory", &H0210, 0)
If Not objFolder Is Nothing Then
    Wscript.Echo objFolder.Items().Item().Path
End If
`;
            fs.writeFileSync(vbsPath, vbsCode);

            exec(`cscript //Nologo "${vbsPath}"`, (error, stdout, stderr) => {
                try { fs.unlinkSync(vbsPath); } catch {}
                if (error) {
                    logger.error('VBS picker failed', { stderr: stderr || error.message });
                    reject(new Error(`Picker Error: ${stderr || error.message}`));
                    return;
                }
                const cleanPath = stdout.trim();
                if (!cleanPath) return reject(new Error('No directory selected (Dialog cancelled)'));
                resolve(cleanPath);
            });
        } else {
            // Linux (Requires Zenity)
            exec(`zenity --file-selection --directory --title="Select Source Code Directory"`, (error, stdout, stderr) => {
                if (error) {
                    logger.error('Linux picker failed', { stderr: stderr || error.message });
                    reject(new Error(`Picker Error (Linux): Ensure 'zenity' is installed or type path manually.`));
                    return;
                }
                const cleanPath = stdout.trim();
                if (!cleanPath) return reject(new Error('No directory selected (Dialog cancelled)'));
                resolve(cleanPath);
            });
        }
    });
}

export function extractZipArchive(zipFilePath: string, destDir: string): Promise<string> {
    return new Promise((resolve, reject) => {
        try {
            if (!fs.existsSync(destDir)) {
                fs.mkdirSync(destDir, { recursive: true });
            }
            const zip = new AdmZip(zipFilePath);
            zip.extractAllTo(destDir, true);
            
            // If the zip contains exactly one top-level directory, that's our real source
            const entries = fs.readdirSync(destDir);
            let finalDir = destDir;
            if (entries.length === 1) {
                const possibleWrapper = path.join(destDir, entries[0]);
                if (fs.statSync(possibleWrapper).isDirectory()) {
                    finalDir = possibleWrapper;
                }
            }
            resolve(finalDir);
        } catch (error) {
            reject(error);
        }
    });
}

export function cloneGitRepository(url: string, token: string | undefined, destDir: string): Promise<string> {
    return new Promise((resolve, reject) => {
        if (!fs.existsSync(destDir)) {
            fs.mkdirSync(destDir, { recursive: true });
        }
        
        let cloneUrl = url;
        if (token && cloneUrl.startsWith('https://')) {
            cloneUrl = cloneUrl.replace('https://', `https://${token}@`);
        }
        
        exec(`git clone "${cloneUrl}" "${destDir}"`, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            resolve(destDir);
        });
    });
}
