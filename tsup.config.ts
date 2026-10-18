import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/cli.ts'],
  format: ['esm'],
  target: 'node18',
  clean: true,
  // Deklaracje typów tylko dla publicznego API, CLI ich nie potrzebuje.
  dts: { entry: ['src/index.ts'] },
  shims: false,
  splitting: false,
});
