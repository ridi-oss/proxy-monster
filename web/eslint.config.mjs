import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    '.next/**',
    'out/**',
    'build/**',
    'next-env.d.ts',
  ]),
  {
    rules: {
      // React-Compiler-era rule. We legitimately set state in effects for
      // mount-time browser reads (localStorage/sessionStorage, matchMedia,
      // next-themes mount flag) and for seeding form fields when a dialog opens
      // or its edit target changes — intentional, not cascading-render bugs.
      // Keep it as a hint, not a hard error.
      'react-hooks/set-state-in-effect': 'warn',
    },
  },
]);

export default eslintConfig;
