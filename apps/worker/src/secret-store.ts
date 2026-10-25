import type { RealtimeFanout, SecretStore } from "@lumio/adapter-kit";
import { createSecretStore } from "@lumio/adapters";
import { resolveEncryptionKey } from "@lumio/core";

/** Worker composition without starting job hosts or database connections. */
export async function createWorkerSecretStore(
  source: NodeJS.ProcessEnv,
  realtime?: RealtimeFanout,
): Promise<SecretStore> {
  const store = createSecretStore(resolveEncryptionKey(source), source, realtime);
  await store.start();
  return store;
}
