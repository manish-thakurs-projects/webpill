import { config } from 'dotenv';
import { fileURLToPath } from 'node:url';

config({ path: fileURLToPath(new URL('../../../.env', import.meta.url)) });

const [{ default: mongoose }, { app }] = await Promise.all([
  import('mongoose'),
  import('./app.js'),
]);

const port = Number(process.env.PORT ?? 3001);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}

if (process.env.MONGODB_URI) {
  mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5_000 })
    .then(() => console.info(JSON.stringify({ level: 'info', event: 'mongodb_connected' })))
    .catch((error: unknown) => {
      console.warn(JSON.stringify({
        level: 'warn',
        event: 'mongodb_unavailable',
        detail: error instanceof Error ? error.message : 'Unknown database error',
        fallback: 'in-memory cache',
      }));
    });
}

const server = app.listen(port, () => {
  console.info(JSON.stringify({ level: 'info', event: 'api_started', port }));
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    server.close(() => {
      void mongoose.disconnect().finally(() => process.exit(0));
    });
  });
}
