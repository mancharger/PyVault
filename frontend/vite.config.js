import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    alias: {
      'argon2-browser': 'argon2-browser/dist/argon2-bundled.min.js'
    }
  }
});
