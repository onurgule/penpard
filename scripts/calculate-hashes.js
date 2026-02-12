/**
 * Calculate SHA512 hashes for distribution files
 * Used for generating update server YAML files
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, '..', 'dist');

function calculateHash(filePath) {
    if (!fs.existsSync(filePath)) {
        return null;
    }
    const fileBuffer = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha512').update(fileBuffer).digest('base64');
    const size = fs.statSync(filePath).size;
    return { hash, size };
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

console.log('');
console.log('===========================================');
console.log('  PenPard Distribution File Hashes');
console.log('===========================================');
console.log('');

if (!fs.existsSync(distDir)) {
    console.log('Error: dist directory not found.');
    console.log('Run "npm run pack:all" first to generate distribution files.');
    process.exit(1);
}

const files = fs.readdirSync(distDir).filter(f => 
    f.endsWith('.exe') || 
    f.endsWith('.dmg') || 
    f.endsWith('.AppImage') ||
    f.endsWith('.deb')
);

if (files.length === 0) {
    console.log('No distribution files found in dist/');
    console.log('Run "npm run pack:all" first.');
    process.exit(1);
}

const results = [];

files.forEach(file => {
    const filePath = path.join(distDir, file);
    const result = calculateHash(filePath);
    if (result) {
        results.push({
            file,
            ...result
        });
        
        console.log(`📦 ${file}`);
        console.log(`   Size: ${formatBytes(result.size)}`);
        console.log(`   SHA512: ${result.hash.substring(0, 40)}...`);
        console.log('');
    }
});

// Generate YAML snippets
console.log('===========================================');
console.log('  YAML Snippets for Update Server');
console.log('===========================================');
console.log('');

results.forEach(r => {
    console.log(`# ${r.file}`);
    console.log(`- url: ${r.file}`);
    console.log(`  sha512: ${r.hash}`);
    console.log(`  size: ${r.size}`);
    console.log('');
});
