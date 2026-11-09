import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/',
      '**/.wrangler/',
      'node_modules/',
      'worker-configuration.d.ts',
      'test-results/',
      'playwright-report/',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    files: ['eslint.config.js', 'scripts/**/*.mjs', 'e2e/**/*.mjs', 'public/**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    // Browser script served as a static asset (second-factor pages).
    files: ['public/**/*.js'],
    languageOptions: {
      sourceType: 'module',
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        fetch: 'readonly',
        atob: 'readonly',
        btoa: 'readonly',
      },
    },
  },
  {
    files: ['scripts/**/*.mjs', 'e2e/**/*.mjs'],
    languageOptions: { globals: { console: 'readonly', process: 'readonly' } },
  },
);
