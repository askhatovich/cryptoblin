// Generate web/src/version.js from version.js.in. Lets the web bundle build
// stand on its own without needing CMake to have run first (the C++ build
// uses configure_file() for the same template).
//
// Substitutions match those in src/CMakeLists.txt:
//   @APP_VERSION@      → $APP_VERSION env var, or `git describe --tags --dirty`
//   @GIT_SHORT_HASH@   → `git rev-parse --short HEAD`

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC  = join(__dirname, '..', 'src', 'version.js.in');
const DEST = join(__dirname, '..', 'src', 'version.js');

function tryGit(cmd, fallback) {
    try {
        return execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] })
            .toString()
            .trim();
    } catch {
        return fallback;
    }
}

const version = (process.env.APP_VERSION
    || tryGit('git describe --tags --dirty', 'dev'))
    .replace(/^v/, '');
const shortHash = tryGit('git rev-parse --short HEAD', 'unknown');

const tpl = readFileSync(SRC, 'utf8');
const out = tpl
    .replace(/@APP_VERSION@/g,    version)
    .replace(/@GIT_SHORT_HASH@/g, shortHash);

writeFileSync(DEST, out);
console.log(`gen-version: ${version} (${shortHash})`);
