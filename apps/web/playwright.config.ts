import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.E2E_PORT ?? 3210);
const externalBaseUrl = process.env.E2E_BASE_URL?.trim();
const localBaseUrl = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  // Run specs sequentially. The dev server (`next dev`) is shared
  // across workers, and parallel page loads pile up enough router /
  // bundle work that page.goto() can take 30+ seconds even when the
  // API surface is fully mocked. Serialising removes that contention
  // and the whole suite still finishes in ~1.5–2 min on a laptop.
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: externalBaseUrl || localBaseUrl,
    trace: "on-first-retry",
  },
  webServer: externalBaseUrl
    ? undefined
    : {
        command: `pnpm exec next dev -p ${port}`,
        url: localBaseUrl,
        reuseExistingServer: true,
        timeout: 120_000,
      },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
