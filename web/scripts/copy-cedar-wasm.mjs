// Copy the Cedar WASM binary out of node_modules into public/ so the browser can
// fetch it as a static asset (avoids bundler-specific WASM handling). Runs via the
// predev/prebuild hooks; public/cedar/ is gitignored. Re-runs on every dev/build,
// so it stays in sync with the installed @cedar-policy/cedar-wasm version.
import { cpSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const src = 'node_modules/@cedar-policy/cedar-wasm/web/cedar_wasm_bg.wasm';
const dest = 'public/cedar/cedar_wasm_bg.wasm';

mkdirSync(dirname(dest), { recursive: true });
cpSync(src, dest);
console.log(`copy-cedar-wasm: ${src} -> ${dest}`);
