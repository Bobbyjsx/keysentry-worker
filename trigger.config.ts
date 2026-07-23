import { defineConfig } from '@trigger.dev/sdk/v3';

export default defineConfig({
  dirs: ['src/tasks'],
  logLevel: 'log',
  maxDuration: 3600,
  project: 'proj_rmftovjsfngdonvuhxtp',
  retries: {
    default: {
      factor: 2,
      maxAttempts: 3,
      maxTimeoutInMs: 10000,
      minTimeoutInMs: 1000,
      randomize: true,
    },
    enabledInDev: true,
  },
  runtime: 'node',
});
