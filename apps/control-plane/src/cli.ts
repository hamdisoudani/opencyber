import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { serve } from '@hono/node-server';
import dotenv from 'dotenv';
import { createControlPlaneServer } from './server.js';
import { ProgramWorkspaceManager } from './workspace-manager.js';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const rootEnvPath = path.resolve(currentDir, '../../../.env');
dotenv.config({ path: rootEnvPath });

async function main(): Promise<void> {
  const port = Number.parseInt(process.env.PORT ?? '4100', 10) || 4100;
  const explicitHost = process.env.HOST?.trim();
  const dataDir = process.env.AEGIS_DATA_DIR
    ? path.resolve(process.env.AEGIS_DATA_DIR)
    : path.resolve(currentDir, '../.aegis-runtime');

  const manager = new ProgramWorkspaceManager({
    dataDir,
    useDemoTarget: false,
    useCloudSandbox: true,
  });

  await manager.init();
  const app = createControlPlaneServer(manager);

  const serveOptions = explicitHost
    ? { fetch: app.fetch, hostname: explicitHost, port }
    : { fetch: app.fetch, port };

  const server = serve(serveOptions, (info) => {
    const displayHost = explicitHost || '0.0.0.0';
    console.log(
      `[aegis-control-plane] Listening on http://${displayHost}:${info.port} (mode=chat-first-multi-program, orchestrator=${manager.llmRouter.orchestratorProvider}:${manager.llmRouter.orchestratorModel})`,
    );
  });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    console.log(`[aegis-control-plane] Received ${signal}, shutting down...`);
    server.close();
    await manager.close();
    process.exit(0);
  };

  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
}

main().catch((err: unknown) => {
  const message =
    err instanceof Error ? err.stack || err.message : String(err);
  console.error(`[aegis-control-plane] Fatal startup error: ${message}`);
  process.exit(1);
});
