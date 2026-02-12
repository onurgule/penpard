/**
 * Convert PNG to ICO with multiple sizes
 */
const fs = require('fs');
const path = require('path');

const inputPath = path.join(__dirname, '..', 'electron', 'assets', 'icon.png');
const outputPath = path.join(__dirname, '..', 'electron', 'assets', 'icon.ico');

async function convert() {
    try {
        console.log('Converting PNG to ICO...');
        console.log(`Input: ${inputPath}`);
        console.log(`Output: ${outputPath}`);
        
        // Dynamic import for ES module
        const pngToIco = (await import('png-to-ico')).default;
        
        const buf = await pngToIco([inputPath]);
        fs.writeFileSync(outputPath, buf);
        
        console.log('ICO file created successfully!');
        
        // Verify file
        const stats = fs.statSync(outputPath);
        console.log(`File size: ${stats.size} bytes`);
    } catch (error) {
        console.error('Error converting:', error);
        process.exit(1);
    }
}

convert();
