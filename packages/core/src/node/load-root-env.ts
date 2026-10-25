import { existsSync } from "node:fs";
import path from "node:path";
import { config } from "dotenv";

/** Keep previous RAKAZO_* names working next to LUMIO_*. */
export function aliasLegacyProductEnv(env: NodeJS.ProcessEnv = process.env) {
  for (const [key, value] of Object.entries(env)) {
    if (value == null || value === "") continue;
    if (key.startsWith("LUMIO_")) {
      const previous = `RAKAZO_${key.slice("LUMIO_".length)}`;
      if (env[previous] == null) env[previous] = value;
    } else if (key.startsWith("RAKAZO_")) {
      const next = `LUMIO_${key.slice("RAKAZO_".length)}`;
      if (env[next] == null) env[next] = value;
    }
  }
}

export function loadRootEnv(options: { allowInTests?: boolean } = {}) {
  // Test runners and verification CLIs supply their own isolated environment.
  // Loading a developer's credentials here also changes otherwise offline tests.
  if (process.env.NODE_ENV === "test" && !options.allowInTests) return;
  let dir = process.cwd();
  for (let i = 0; i < 8; i += 1) {
    const candidate = path.join(dir, ".env");
    if (existsSync(candidate)) {
      config({ path: candidate, override: false });
      if (process.env.DATA_DIR && !path.isAbsolute(process.env.DATA_DIR)) {
        process.env.DATA_DIR = path.resolve(dir, process.env.DATA_DIR);
      }
      aliasLegacyProductEnv();
      return;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  config();
  aliasLegacyProductEnv();
}
