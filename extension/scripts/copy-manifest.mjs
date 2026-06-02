import { copyFileSync, mkdirSync } from 'fs';

mkdirSync('dist', { recursive: true });
copyFileSync('manifest.json', 'dist/manifest.json');
