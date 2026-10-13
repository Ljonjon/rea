import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { readClientRegistrationStatuses } from "../../../src/application/ClientRegistrationStatus.js";
import { npxRegistrationCommand } from "../../../src/application/ClientRegistrationIdentity.js";
import { configureClientConfiguration } from "../../../src/application/SetupClientConfiguration.js";
import { skillDestinations } from "../../../src/application/SetupSkill.js";
import { supportedClients } from "../../../src/application/SupportedClients.js";
import { systemUninstallHost } from "../../../src/application/Uninstall.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { clearClientLocationEnvironment } from "../../fixtures/clientEnvironment.js";

/**
 * The registration command setup writes on the host running the tests. Windows
 * wraps it in `cmd.exe /d /c`, so the expected entry follows the host too.
 */
const command = npxRegistrationCommand(process.platform);

beforeEach(clearClientLocationEnvironment);
afterEach(() => vi.unstubAllEnvs());

const freebuffPath = (
  home: string,
  platform: NodeJS.Platform = "linux",
  env: Parameters<typeof supportedClients>[2] = {},
) =>
  supportedClients(home, platform, env).find(({ name }) => name === "freebuff");

describe("FreeBuff configuration paths", () => {
  it("resolves the shared user agents file and marker directory", () => {
    expect(freebuffPath("/home/a")).toEqual({
      name: "freebuff",
      displayName: "FreeBuff",
      configPath: join("/home/a", ".agents", "mcp.json"),
      markerPath: join("/home/a", ".agents"),
      format: "json",
    });
    expect(freebuffPath("/Users/a", "darwin")?.configPath).toBe(
      join("/Users/a", ".agents", "mcp.json"),
    );
    expect(freebuffPath("C:\\Users\\a", "win32")?.configPath).toBe(
      join("C:\\Users\\a", ".agents", "mcp.json"),
    );
  });

  it("shares the user-scope file ZCode loads as its fallback", () => {
    const clients = supportedClients("/home/a", "linux", {});
    const freebuff = clients.find(({ name }) => name === "freebuff");
    const zcode = clients.find(({ name }) => name === "zcode");
    expect(freebuff?.configPath).toBe(zcode?.zcodeFallbackPath);
  });

  it("resolves the personal skills directory FreeBuff discovers", () => {
    expect(skillDestinations("/home/a", ["freebuff"])).toEqual([
      {
        client: "shared",
        path: join("/home/a", ".agents", "skills", "reverse-engineer-anything"),
      },
    ]);
  });
});

describe("FreeBuff JSON registration", () => {
  const freebuffClient = async () => {
    const home = await createTestTempDirectory("rea-freebuff-");
    const client = freebuffPath(home, process.platform);
    if (client?.markerPath === undefined)
      throw new Error("missing FreeBuff client");
    await mkdir(client.markerPath, { recursive: true });
    return { home, client };
  };

  it("upserts rea into mcpServers while preserving unrelated settings", async () => {
    const { home, client } = await freebuffClient();
    await writeFile(
      client.configPath,
      `{
  "mcpServers": {
    "other": { "command": "other-server" }
  },
  "agents": { "discoverSkills": true }
}`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const parsed = JSON.parse(await readFile(client.configPath, "utf8"));
    expect(parsed.mcpServers.other).toEqual({ command: "other-server" });
    expect(parsed.agents).toEqual({ discoverSkills: true });
    expect(parsed.mcpServers.rea).toEqual({
      command: command[0],
      args: command.slice(1),
    });

    expect(await configureClientConfiguration(client, {}, command)).toEqual({
      status: "unchanged",
    });
    expect(
      (
        await readClientRegistrationStatuses(home, undefined, {
          platform: process.platform,
          environment: {},
        })
      ).find(({ client }) => client === "freebuff"),
    ).toMatchObject({ state: "aligned", command });
  });

  it("creates the mcpServers table in an existing file without servers", async () => {
    const { client } = await freebuffClient();
    await writeFile(
      client.configPath,
      JSON.stringify({ agents: { discoverSkills: true } }, null, 2),
    );
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const parsed = JSON.parse(await readFile(client.configPath, "utf8"));
    expect(parsed.agents).toEqual({ discoverSkills: true });
    expect(parsed.mcpServers.rea).toEqual({
      command: command[0],
      args: command.slice(1),
    });
  });

  it("registers into an empty settings file", async () => {
    const { client } = await freebuffClient();
    await writeFile(client.configPath, "");
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const parsed = JSON.parse(await readFile(client.configPath, "utf8"));
    expect(parsed.mcpServers.rea).toEqual({
      command: command[0],
      args: command.slice(1),
    });
  });

  it("removes only the rea entry on uninstall", async () => {
    const { home, client } = await freebuffClient();
    await writeFile(
      client.configPath,
      JSON.stringify(
        { mcpServers: { other: { command: "other-server" } } },
        null,
        2,
      ),
    );
    await configureClientConfiguration(client, {}, command);

    expect((await systemUninstallHost(home).removeClient(client)).status).toBe(
      "removed",
    );
    const parsed = JSON.parse(await readFile(client.configPath, "utf8"));
    expect(parsed.mcpServers.other).toEqual({ command: "other-server" });
    expect(parsed.mcpServers.rea).toBeUndefined();
  });
});
