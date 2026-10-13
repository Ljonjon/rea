import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { parseBinaryTarget } from "../../../../src/application/BinaryTargetResolver.js";
import { managedMemberInspectionSchema } from "../../../../src/domain/managed/managedArtifact.js";
import { ManagedStaticProvider } from "../../../../src/dotnet/ManagedStaticProvider.js";
import { buildManagedPeFixture } from "../../../../src/dotnet/ManagedPe.fixture.js";
import {
  buildPortablePdbFixture,
  portablePdbGuidBytes,
  PORTABLE_PDB_FIXTURE_STAMP,
  PORTABLE_PDB_FIXTURE_GUID,
} from "../../../../src/dotnet/PortablePdb.fixture.js";
import * as boundedFileBytes from "../../../../src/process/BoundedFileBytes.js";

const codeview = {
  guid: portablePdbGuidBytes(PORTABLE_PDB_FIXTURE_GUID),
  age: 1,
  stamp: PORTABLE_PDB_FIXTURE_STAMP,
};

const fixturePdb = () =>
  buildPortablePdbFixture({
    documents: [
      {
        name: "/src/Program.cs",
        hashAlgorithm: "sha-256",
        language: "csharp",
      },
    ],
    methods: [
      {
        document: 1,
        points: [
          { il: 0, startLine: 5, startColumn: 2, endLine: 5, endColumn: 20 },
          { il: 4, hidden: true },
        ],
      },
    ],
  });

describe("managed static provider Portable PDB selection", () => {
  it("reads an explicitly selected Portable PDB and binds it to the assembly", async () => {
    const directory = await createTestTempDirectory("rea-managed-pdb-path-");
    const pePath = join(directory, "fixture.exe");
    const pdbPath = join(directory, "fixture.pdb");
    const pdbBytes = fixturePdb();
    await writeFile(pePath, buildManagedPeFixture({ codeview }));
    await writeFile(pdbPath, pdbBytes);
    const parsed = await parseBinaryTarget(pePath);
    if (!parsed.ok) throw parsed.error;
    const client = new ManagedStaticProvider().createClient(parsed.value);
    try {
      const execution = await client.execute("inspect_managed_members", {
        pdb_path: pdbPath,
      });
      if (!execution.ok) throw execution.error;
      const result = managedMemberInspectionSchema.parse(
        execution.value.result,
      );
      expect(result.debug_map).toMatchObject({
        status: "bound",
        source: {
          kind: "external",
          path: pdbPath,
          sha256: createHash("sha256").update(pdbBytes).digest("hex"),
          byte_length: pdbBytes.length,
        },
        identity: { status: "matched" },
        documents: [
          expect.objectContaining({
            name: "/src/Program.cs",
            hash_algorithm: "sha-256",
          }),
        ],
        methods: [
          expect.objectContaining({
            token: "0x06000001",
            sequence_points: [
              expect.objectContaining({ il_offset: 0, hidden: false }),
              expect.objectContaining({ il_offset: 4, hidden: true }),
            ],
          }),
        ],
      });
      expect(result.methods[0]?.token).toBe("0x06000001");
    } finally {
      await client.close();
    }
  });

  it("binds the embedded Portable PDB through pdb_embedded", async () => {
    const directory = await createTestTempDirectory("rea-managed-pdb-embed-");
    const pePath = join(directory, "fixture.exe");
    await writeFile(
      pePath,
      buildManagedPeFixture({ codeview, embeddedPortablePdb: fixturePdb() }),
    );
    const parsed = await parseBinaryTarget(pePath);
    if (!parsed.ok) throw parsed.error;
    const client = new ManagedStaticProvider().createClient(parsed.value);
    try {
      const execution = await client.execute("inspect_managed_members", {
        pdb_embedded: true,
      });
      if (!execution.ok) throw execution.error;
      const result = managedMemberInspectionSchema.parse(
        execution.value.result,
      );
      expect(result.debug_map).toMatchObject({
        status: "bound",
        source: { kind: "embedded" },
        identity: { status: "matched" },
      });
    } finally {
      await client.close();
    }
  });
});

describe("managed static provider Portable PDB input failures", () => {
  it("rejects a missing pdb_path as caller input, keeping provider cleanup intact", async () => {
    const directory = await createTestTempDirectory("rea-managed-pdb-missing-");
    const pePath = join(directory, "fixture.exe");
    await writeFile(pePath, buildManagedPeFixture({ codeview }));
    const parsed = await parseBinaryTarget(pePath);
    if (!parsed.ok) throw parsed.error;
    const client = new ManagedStaticProvider().createClient(parsed.value);
    try {
      const result = await client.execute("inspect_managed_members", {
        pdb_path: join(directory, "missing.pdb"),
      });
      expect(result).toMatchObject({ ok: false });
      // The member inspection still works once the bad selector is removed.
      const recovered = await client.execute("inspect_managed_members", {});
      expect(recovered.ok).toBe(true);
      expect(await client.close()).toMatchObject({ ok: true });
    } finally {
      await client.close();
    }
  });

  it("rejects pdb_path combined with pdb_embedded as conflicting input", async () => {
    const directory = await createTestTempDirectory(
      "rea-managed-pdb-conflict-",
    );
    const pePath = join(directory, "fixture.exe");
    const pdbPath = join(directory, "fixture.pdb");
    await writeFile(pePath, buildManagedPeFixture({ codeview }));
    await writeFile(pdbPath, fixturePdb());
    const parsed = await parseBinaryTarget(pePath);
    if (!parsed.ok) throw parsed.error;
    const client = new ManagedStaticProvider().createClient(parsed.value);
    try {
      const result = await client.execute("inspect_managed_members", {
        pdb_path: pdbPath,
        pdb_embedded: true,
      });
      expect(result).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
    } finally {
      await client.close();
    }
  });

  it("rejects a relative pdb_path as caller input", async () => {
    const directory = await createTestTempDirectory(
      "rea-managed-pdb-relative-",
    );
    const pePath = join(directory, "fixture.exe");
    await writeFile(pePath, buildManagedPeFixture({ codeview }));
    const parsed = await parseBinaryTarget(pePath);
    if (!parsed.ok) throw parsed.error;
    const client = new ManagedStaticProvider().createClient(parsed.value);
    try {
      const result = await client.execute("inspect_managed_members", {
        pdb_path: "relative/fixture.pdb",
      });
      expect(result).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
    } finally {
      await client.close();
    }
  });

  it("propagates cancellation while reading the selected PDB file", async () => {
    const directory = await createTestTempDirectory("rea-managed-pdb-cancel-");
    const pePath = join(directory, "fixture.exe");
    const pdbPath = join(directory, "fixture.pdb");
    await writeFile(pePath, buildManagedPeFixture({ codeview }));
    await writeFile(pdbPath, fixturePdb());
    const parsed = await parseBinaryTarget(pePath);
    if (!parsed.ok) throw parsed.error;
    const client = new ManagedStaticProvider().createClient(parsed.value);
    const controller = new AbortController();
    const originalRead = boundedFileBytes.readBoundedFileBytes;
    let pdbReads = 0;
    const read = vi
      .spyOn(boundedFileBytes, "readBoundedFileBytes")
      .mockImplementation(async (...arguments_) => {
        pdbReads += 1;
        // First read is the assembly snapshot; abort during the PDB read.
        if (pdbReads === 2) controller.abort(new Error("fixture cancellation"));
        return originalRead(...arguments_);
      });
    try {
      const result = await client.execute(
        "inspect_managed_members",
        { pdb_path: pdbPath },
        { signal: controller.signal },
      );
      expect(result).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisCancelledError" },
      });
    } finally {
      read.mockRestore();
      await client.close();
    }
  });
});
