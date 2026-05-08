import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["smoke.test.ts", "lib/**/*.test.ts", "security-headers.test.ts"],
    exclude: ["e2e/**"],
  },
});
