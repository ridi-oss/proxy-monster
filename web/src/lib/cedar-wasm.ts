'use client';

// Lazy loader for the Cedar WASM SDK (~4MB), used by the Cedar policy editor's
// linter (@ridi/codemirror-lang-cedar). The binary is served as a static
// asset from /cedar/ (copied out of node_modules by scripts/copy-cedar-wasm.mjs),
// so no bundler-specific WASM handling is needed. It is imported dynamically and
// initialized once, only when a caller actually opens the editor.

import { useEffect, useState } from 'react';
import type { CedarWasmModule } from '@ridi/codemirror-lang-cedar';

let loader: Promise<CedarWasmModule> | null = null;

async function loadCedarWasm(): Promise<CedarWasmModule> {
  if (!loader) {
    loader = (async () => {
      const mod = await import('@cedar-policy/cedar-wasm/web');
      await mod.default({ module_or_path: '/cedar/cedar_wasm_bg.wasm' });
      // Syntax checking (policySetTextToParts + checkParsePolicySet) plus, when a
      // schema is supplied, strict type validation (validate) and schema-aware
      // completion (schemaToJson).
      return {
        policySetTextToParts: mod.policySetTextToParts,
        checkParsePolicySet: mod.checkParsePolicySet,
        validate: mod.validate,
        schemaToJson: mod.schemaToJson,
      } as CedarWasmModule;
    })();
  }
  return loader;
}

/**
 * Load the Cedar WASM once [enabled] is true; returns null until it's ready (or if
 * loading fails — the editor then simply has no live linting). The load is cached
 * process-wide, so opening the editor repeatedly initializes the WASM only once.
 */
export function useCedarWasm(enabled: boolean): CedarWasmModule | null {
  const [wasm, setWasm] = useState<CedarWasmModule | null>(null);
  useEffect(() => {
    if (!enabled || wasm) return;
    let cancelled = false;
    loadCedarWasm()
      .then((m) => {
        if (!cancelled) setWasm(m);
      })
      .catch(() => {
        /* no live linting if the WASM can't load — server-side Validate still works */
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, wasm]);
  return wasm;
}
