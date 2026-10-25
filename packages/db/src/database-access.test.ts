import { describe, expect, it } from "vitest";
import { databaseUrls, rowSecurityWarning } from "./database-access.js";

const owner = "postgres://lumio:owner-password@postgres:5432/lumio";
const runtime = "postgres://lumio_app:app-password@postgres:5432/lumio";

describe("databaseUrls", () => {
  it("migrates as the owner and runs the app as the runtime login", () => {
    expect(databaseUrls({ DATABASE_URL: runtime, DATABASE_MIGRATION_URL: owner })).toEqual({
      url: runtime,
      migrationUrl: owner,
      separate: true,
    });
  });

  it("falls back to one shared login when only DATABASE_URL is set", () => {
    expect(databaseUrls({ DATABASE_URL: owner })).toEqual({
      url: owner,
      migrationUrl: owner,
      separate: false,
    });
    expect(databaseUrls({ DATABASE_URL: owner, DATABASE_MIGRATION_URL: " " }).separate).toBe(false);
  });

  it("treats two URLs for the same login as shared", () => {
    const sameLogin = "postgres://lumio:owner-password@127.0.0.1:5433/lumio";
    expect(databaseUrls({ DATABASE_URL: sameLogin, DATABASE_MIGRATION_URL: owner }).separate).toBe(
      false,
    );
  });

  it("requires DATABASE_URL", () => {
    expect(() => databaseUrls({ DATABASE_MIGRATION_URL: owner })).toThrow("DATABASE_URL");
  });
});

describe("rowSecurityWarning", () => {
  it("is silent when the policies apply", () => {
    expect(rowSecurityWarning({ enforced: true, role: "lumio_app" })).toBeUndefined();
  });

  it("names the login and why it bypasses the policies", () => {
    expect(
      rowSecurityWarning({ enforced: false, role: "lumio", reason: "is a superuser" }),
    ).toContain("connects as lumio, which is a superuser");
  });
});
