import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { aliasLegacyProductEnv, loadRootEnv } from "./load-root-env.js";

let root: string;
beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), "lumio-env-test-"));
  writeFileSync(path.join(root, ".env"), "LUMIO_TEST_ENV_SENTINEL=fixture\nDATA_DIR=./data\n");
  vi.spyOn(process, "cwd").mockReturnValue(root);
  vi.stubEnv("LUMIO_TEST_ENV_SENTINEL", undefined);
  vi.stubEnv("DATA_DIR", undefined);
  vi.stubEnv("VERIFY_PROVIDERS", undefined);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  rmSync(root, { recursive: true, force: true });
});

describe("root environment loading", () => {
  it("does not import local configuration into test processes", () => {
    vi.stubEnv("NODE_ENV", "test");
    loadRootEnv();
    expect(process.env.LUMIO_TEST_ENV_SENTINEL).toBeUndefined();
    expect(process.env.DATA_DIR).toBeUndefined();
  });

  it("loads development configuration and anchors relative data paths to its directory", () => {
    vi.stubEnv("NODE_ENV", "development");
    loadRootEnv();
    expect(process.env.LUMIO_TEST_ENV_SENTINEL).toBe("fixture");
    expect(process.env.DATA_DIR).toBe(path.join(root, "data"));
  });

  it("preserves configuration supplied by the caller", () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("LUMIO_TEST_ENV_SENTINEL", "caller");
    loadRootEnv();
    expect(process.env.LUMIO_TEST_ENV_SENTINEL).toBe("caller");
  });

  it("loads configuration when a live verification explicitly opts in", () => {
    vi.stubEnv("NODE_ENV", "test");
    loadRootEnv({ allowInTests: true });
    expect(process.env.LUMIO_TEST_ENV_SENTINEL).toBe("fixture");
  });

  it("mirrors LUMIO_* values onto RAKAZO_* when the previous name is unset", () => {
    const env: NodeJS.ProcessEnv = { LUMIO_HOST: "lumio.example" };
    aliasLegacyProductEnv(env);
    expect(env.LUMIO_HOST).toBe("lumio.example");
    expect(env.RAKAZO_HOST).toBe("lumio.example");
  });

  it("mirrors RAKAZO_* values onto LUMIO_* without overwriting a set name", () => {
    const env: NodeJS.ProcessEnv = { RAKAZO_HOST: "legacy.example", LUMIO_HOST: "lumio.example" };
    aliasLegacyProductEnv(env);
    expect(env.LUMIO_HOST).toBe("lumio.example");
    expect(env.RAKAZO_HOST).toBe("legacy.example");
  });
});
