import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    /*
     * configDefaults.exclude is SPREAD IN, not replaced.
     *
     * `exclude` overrides the defaults rather than adding to them, so writing a bare list silently
     * turns off every default exclusion. The old value here was ['src/__tests__/integration/**',
     * 'node_modules/**'], and node_modules was in it precisely because someone had already hit this
     * and patched the half they noticed. The half they did not notice was dist/**: anyone with a
     * local build got six failing suites full of "Vitest cannot be imported in a CommonJS module",
     * from compiled copies of the same tests, none of it related to whatever they had changed.
     */
    exclude: [...configDefaults.exclude, 'src/__tests__/integration/**', 'dist/**'],
  },
});
