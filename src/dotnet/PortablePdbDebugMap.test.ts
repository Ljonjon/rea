import { describe, expect, it } from "vitest";

import { managedMemberInspectionSchema } from "../domain/managed/managedArtifact.js";

import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import {
  buildManagedPeFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";
import {
  buildPortablePdbFixture,
  portablePdbGuidBytes,
  PORTABLE_PDB_FIXTURE_GUID,
  PORTABLE_PDB_FIXTURE_STAMP,
  portablePdbStamp,
} from "./PortablePdb.fixture.js";

// Mirrors a real producer pair: RSDS Age is always 1 for Portable PDBs;
// identity is the GUID plus the debug-entry TimeDateStamp.
const matchingCodeview = {
  guid: portablePdbGuidBytes(PORTABLE_PDB_FIXTURE_GUID),
  age: 1,
  stamp: PORTABLE_PDB_FIXTURE_STAMP,
  path: "/src/fixture.pdb",
};

const memberInspection = (
  pe: Buffer,
  pdb?:
    | { kind: "external"; path: string; bytes: Buffer; sha256: string }
    | {
        kind: "embedded";
      },
) =>
  managedMemberInspectionSchema.parse(
    inspectManagedMembersBytes(
      pe,
      managedPeFixtureTarget(pe),
      pdb === undefined ? {} : { pdb },
    ),
  );

const externalPdb = (bytes: Buffer, path = "/src/fixture.pdb") => ({
  kind: "external" as const,
  path,
  bytes,
  sha256: "0".repeat(64),
});

describe("Portable PDB debug map binding", () => {
  it("reports debug_map as null when no PDB selector is supplied", () => {
    const result = memberInspection(buildManagedPeFixture());
    expect(result.debug_map).toBeNull();
  });

  it("binds a matching external Portable PDB to build-local method tokens", () => {
    const pdb = buildPortablePdbFixture({
      documents: [
        {
          name: "/src/Program.cs",
          hashAlgorithm: "sha-256",
          hash: Buffer.from("11".repeat(32), "hex"),
          language: "csharp",
        },
      ],
      methods: [
        {
          document: 1,
          points: [
            {
              il: 0,
              startLine: 10,
              startColumn: 5,
              endLine: 10,
              endColumn: 30,
            },
            { il: 3, hidden: true },
            { il: 5, startLine: 12, startColumn: 9, endLine: 14, endColumn: 2 },
          ],
        },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map).toMatchObject({
      status: "bound",
      source: { kind: "external", path: "/src/fixture.pdb" },
      identity: {
        status: "matched",
        declared: {
          codeview: {
            guid: PORTABLE_PDB_FIXTURE_GUID,
            age: 1,
            stamp: PORTABLE_PDB_FIXTURE_STAMP,
            declared_path: "/src/fixture.pdb",
          },
        },
      },
      documents: [
        expect.objectContaining({
          token: "0x30000001",
          name: "/src/Program.cs",
          hash_algorithm: "sha-256",
          hash: "11".repeat(32),
          language: "csharp",
        }),
      ],
      methods: [
        expect.objectContaining({
          token: "0x06000001",
          state: "decoded",
          document_token: "0x30000001",
          sequence_points: [
            expect.objectContaining({
              il_offset: 0,
              start_line: 10,
              start_column: 5,
              end_line: 10,
              end_column: 30,
              hidden: false,
              document_token: "0x30000001",
            }),
            expect.objectContaining({
              il_offset: 3,
              hidden: true,
              start_line: 0xfe_efee,
              document_token: "0x30000001",
            }),
            expect.objectContaining({
              il_offset: 5,
              start_line: 12,
              start_column: 9,
              end_line: 14,
              end_column: 2,
              hidden: false,
            }),
          ],
        }),
      ],
    });
    expect(result.debug_map?.pdb?.entry_point_token).toBe("0x06000001");
    expect(result.debug_map?.identity.checks).toContainEqual(
      expect.objectContaining({ name: "rsds-stamp", result: "matched" }),
    );
    expect(result.debug_map?.identity.checks).toContainEqual(
      expect.objectContaining({ name: "entry-point", result: "matched" }),
    );
    expect(result.debug_map?.identity.checks).toContainEqual(
      expect.objectContaining({ name: "methoddef-rows", result: "matched" }),
    );
    expect(result.coverage.state).toBe("complete");
  });

  it("tracks document switches inside a method spanning multiple documents", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/A.cs" }, { name: "/src/B.cs" }],
      methods: [
        {
          document: 0,
          points: [
            {
              il: 0,
              document: 1,
              startLine: 1,
              startColumn: 1,
              endLine: 1,
              endColumn: 10,
            },
            {
              il: 2,
              document: 2,
              startLine: 5,
              startColumn: 1,
              endLine: 5,
              endColumn: 8,
            },
            { il: 9, startLine: 7, startColumn: 1, endLine: 7, endColumn: 4 },
          ],
        },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    const method = result.debug_map?.methods[0];
    expect(method?.state).toBe("decoded");
    expect(method?.document_token).toBeNull();
    expect(
      method?.sequence_points.map((point) => point.document_token),
    ).toEqual(["0x30000001", "0x30000002", "0x30000002"]);
    expect(
      result.debug_map?.documents.map((document) => document.name),
    ).toEqual(["/src/A.cs", "/src/B.cs"]);
  });
});

describe("Portable PDB identity reporting", () => {
  it("keeps a GUID/age mismatch explicit while still reporting PDB evidence", () => {
    const pdb = buildPortablePdbFixture({
      pdbId: portablePdbStamp("99999999-8888-7777-6666-555555555555", 3),
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.status).toBe("bound");
    expect(result.debug_map?.identity.status).toBe("mismatched");
    expect(result.debug_map?.identity.checks).toContainEqual(
      expect.objectContaining({ name: "rsds-stamp", result: "mismatched" }),
    );
    expect(result.limitations.join("\n")).toContain(
      "does not share the assembly's declared CodeView identity",
    );
  });

  it("matches a producer-shaped pair where RSDS age stays 1", () => {
    // Per PE-COFF, portable CodeView keeps Age=1 and the PDB ID's stamp
    // lives in the debug entry's TimeDateStamp — matching must not use Age.
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.identity.status).toBe("matched");
    expect(result.debug_map?.identity.declared.codeview).toMatchObject({
      age: 1,
      stamp: PORTABLE_PDB_FIXTURE_STAMP,
    });
  });

  it("reports identity as undeclared when the PE has no CodeView entry", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(buildManagedPeFixture(), externalPdb(pdb));
    expect(result.debug_map?.status).toBe("bound");
    expect(result.debug_map?.identity).toMatchObject({
      status: "undeclared",
      declared: { codeview: null, embedded_portable_pdb: false },
    });
  });

  it("marks a Windows MSF PDB as malformed instead of misreading it", () => {
    const msf = Buffer.concat([
      Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0", "latin1"),
      Buffer.alloc(64),
    ]);
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(msf),
    );
    expect(result.debug_map?.status).toBe("malformed");
    expect(result.debug_map?.coverage.issues[0]?.detail).toContain(
      "Windows (MSF) PDB",
    );
    expect(result.debug_map?.identity.status).toBe("unverifiable");
    expect(result.methods[0]?.token).toBe("0x06000001");
  });

  it("extracts and binds the embedded Portable PDB when selected", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 3, startColumn: 2 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({
        codeview: matchingCodeview,
        embeddedPortablePdb: pdb,
      }),
      { kind: "embedded" },
    );
    expect(result.debug_map).toMatchObject({
      status: "bound",
      source: { kind: "embedded" },
      identity: { status: "matched" },
      methods: [
        expect.objectContaining({
          token: "0x06000001",
          state: "decoded",
          sequence_points: [
            expect.objectContaining({ il_offset: 0, start_line: 3 }),
          ],
        }),
      ],
    });
    expect(result.debug_map?.source.sha256).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("reports absent when pdb_embedded is requested but none is declared", () => {
    const result = memberInspection(buildManagedPeFixture(), {
      kind: "embedded",
    });
    expect(result.debug_map?.status).toBe("absent");
    expect(result.debug_map?.identity.declared.embedded_portable_pdb).toBe(
      false,
    );
  });
});

describe("Portable PDB malformed and partial inputs", () => {
  it("marks a sub-header PDB as malformed instead of crashing inspection", () => {
    for (const tiny of [Buffer.alloc(0), Buffer.alloc(3), Buffer.alloc(12)]) {
      const result = memberInspection(
        buildManagedPeFixture({ codeview: matchingCodeview }),
        externalPdb(tiny),
      );
      expect(result.debug_map?.status).toBe("malformed");
      expect(result.debug_map?.identity.status).toBe("unverifiable");
      expect(result.methods[0]?.token).toBe("0x06000001");
    }
  });

  it("marks a truncated sequence-point blob malformed without losing the method", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      referencedStandaloneSignatures: 1,
      methods: [
        {
          document: 1,
          sequencePoints: Buffer.from([0x01, 0x00, 0x80]),
        },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    const method = result.debug_map?.methods[0];
    expect(method?.state).toBe("malformed");
    expect(result.debug_map?.coverage.issues).toContainEqual(
      expect.objectContaining({ scope: "pdb.MethodDebugInformation" }),
    );
    expect(result.debug_map?.documents[0]?.name).toBe("/src/Program.cs");
  });

  it("keeps an out-of-range Document column as an explicit issue", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      referencedStandaloneSignatures: 1,
      methods: [
        {
          document: 9,
          sequencePoints: Buffer.from([0x01, 0x00, 0x01]),
        },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.methods[0]?.state).toBe("malformed");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("beyond the 1-row Document table"),
      ),
    ).toBe(true);
  });

  it("keeps an unreadable document name blob separate from a decoded checksum", () => {
    const pdb = buildPortablePdbFixture({
      documents: [
        {
          name: "/src/Program.cs",
          hashAlgorithm: "sha-384",
          language: "fsharp",
        },
      ],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 2, startColumn: 2 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    const document = result.debug_map?.documents[0];
    expect(document?.hash_algorithm).toBe("sha-384");
    expect(document?.language).toBe("fsharp");
    expect(document?.name).toBe("/src/Program.cs");
  });

  it("keeps unknown checksum algorithm GUIDs visible instead of dropping them", () => {
    const pdb = buildPortablePdbFixture({
      documents: [
        {
          name: "/src/Program.cs",
          hashAlgorithm: "01020304-0506-0708-090a-0b0c0d0e0f10",
          language: "01020304-0506-0708-090a-0b0c0d0e0f10",
        },
      ],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 2, startColumn: 2 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    const document = result.debug_map?.documents[0];
    expect(document?.hash_algorithm).toBeNull();
    expect(document?.hash_algorithm_guid).toBe(
      "01020304-0506-0708-090a-0b0c0d0e0f10",
    );
    expect(document?.language).toBeNull();
    expect(document?.language_guid).toBe(
      "01020304-0506-0708-090a-0b0c0d0e0f10",
    );
  });

  it("flags a MethodDebugInformation row-count disagreement as identity evidence", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
      referencedMethodDefs: 2,
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.identity.checks).toContainEqual(
      expect.objectContaining({ name: "methoddef-rows", result: "mismatched" }),
    );
    expect(result.debug_map?.coverage.issues).toContainEqual(
      expect.objectContaining({ scope: "pdb.MethodDebugInformation" }),
    );
  });
});

describe("Portable PDB declaration and boundary cases", () => {
  it("degrades debug_map to malformed at the representation budget while keeping member evidence", () => {
    // Each hidden point costs 3 encoded bytes but reserves 128 bytes of
    // projection, so ~530k points trip the 64 MiB PDB budget.
    const blob = Buffer.alloc(1 + 3 * 600_000, 0);
    blob[0] = 0x00; // local signature row 0
    for (let offset = 1; offset < blob.length; offset += 3) blob[offset] = 0x01;
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [{ document: 1, sequencePoints: blob }],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.status).toBe("malformed");
    expect(result.debug_map?.coverage.issues).toContainEqual(
      expect.objectContaining({ code: "resource-limit" }),
    );
    // Source and identity were resolved before admission failed; they stay
    // attached to the malformed map instead of reporting absent.
    expect(result.debug_map?.identity.status).toBe("matched");
    expect(result.debug_map?.identity.declared.codeview).toMatchObject({
      guid: PORTABLE_PDB_FIXTURE_GUID,
      stamp: PORTABLE_PDB_FIXTURE_STAMP,
    });
    expect(result.debug_map?.source).toMatchObject({
      kind: "external",
      sha256: "0".repeat(64),
    });
    expect(result.debug_map?.pdb?.guid).toBe(PORTABLE_PDB_FIXTURE_GUID);
    expect(result.methods[0]?.token).toBe("0x06000001");
    expect(result.coverage.state).toBe("complete");
  });

  it("reports unverifiable identity when the declared CodeView entry cannot be read", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    // An RSDS record truncated below GUID + age fails to parse: the
    // declaration was attempted, so identity is unverifiable, not undeclared.
    const result = memberInspection(
      buildManagedPeFixture({
        extraDebugEntries: [{ type: 2, data: Buffer.from("RSDS") }],
      }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.identity.status).toBe("unverifiable");
    expect(result.debug_map?.identity.declared.codeview).toBeNull();
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("shorter than GUID + age"),
      ),
    ).toBe(true);
  });

  it("reports malformed rather than absent when an embedded declaration cannot be read", () => {
    const result = memberInspection(
      buildManagedPeFixture({
        extraDebugEntries: [{ type: 17, data: null }],
      }),
      { kind: "embedded" },
    );
    expect(result.debug_map?.status).toBe("malformed");
    expect(result.debug_map?.identity.status).toBe("unverifiable");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("not file-backed"),
      ),
    ).toBe(true);
  });

  it("counts dropped debug-directory issues in the retained-issue summary", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({
        extraDebugEntries: Array.from({ length: 100 }, () => ({
          type: 5,
          data: null,
        })),
      }),
      externalPdb(pdb),
    );
    // 100 unmappable entries against the 64-issue bound drop 36.
    expect(result.debug_map?.coverage.issues).toContainEqual(
      expect.objectContaining({
        detail: expect.stringContaining("36 further"),
      }),
    );
    // Unrelated entry types stay readable, so PDB presence is not unknown.
    expect(result.debug_map?.identity.status).toBe("undeclared");
  });

  it("keeps embedded selection absent when only unrelated entries fail", () => {
    const result = memberInspection(
      buildManagedPeFixture({
        extraDebugEntries: [{ type: 5, data: null }],
      }),
      { kind: "embedded" },
    );
    expect(result.debug_map?.status).toBe("absent");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("not file-backed"),
      ),
    ).toBe(true);
  });

  it("truncates an oversized RSDS path while keeping identity evidence", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({
        codeview: { ...matchingCodeview, path: "x".repeat(70 * 1024) },
      }),
      externalPdb(pdb),
    );
    const declaredPath =
      result.debug_map?.identity.declared.codeview?.declared_path;
    expect(declaredPath?.length).toBe(64 * 1024);
    expect(result.debug_map?.identity.status).toBe("matched");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("retaining the first 65536"),
      ),
    ).toBe(true);
  });
});

describe("Portable PDB decode boundary cases", () => {
  it("marks hidden sequence points with out-of-range IL offsets malformed", () => {
    // localSig 0; hidden at 0x1fffffff; hidden at +1 -> 0x20000000.
    const sequencePoints = Buffer.from([
      0x00, 0xdf, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00,
    ]);
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [{ document: 1, sequencePoints }],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.methods[0]?.state).toBe("malformed");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("exceeds 0x20000000"),
      ),
    ).toBe(true);
  });

  it("decodes signed line deltas at the two- and four-byte boundaries", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        {
          document: 1,
          points: [
            { il: 0, startLine: 9000, startColumn: 1, endColumn: 8 },
            // startLine delta -8192: smallest two-byte signed encoding.
            { il: 4, startLine: 808, startColumn: 1, endColumn: 8 },
            // startLine delta +268401889: four-byte signed encoding.
            { il: 8, startLine: 268_402_697, startColumn: 1, endColumn: 8 },
            // startLine delta -268402689: four-byte signed encoding whose
            // masked payload fits two bytes but must keep the wider form.
            { il: 12, startLine: 8, startColumn: 1, endColumn: 8 },
          ],
        },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    const method = result.debug_map?.methods[0];
    expect(method?.state).toBe("decoded");
    expect(method?.sequence_points.map((point) => point.start_line)).toEqual([
      9000, 808, 268_402_697, 8,
    ]);
  });

  it("keeps a document's readable columns when its language GUID is invalid", () => {
    const pdb = buildPortablePdbFixture({
      documents: [
        {
          name: "/src/Program.cs",
          hashAlgorithm: "sha-384",
          language: "fsharp",
        },
      ],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 2, startColumn: 2 }] },
      ],
    });
    const pe = buildManagedPeFixture({ codeview: matchingCodeview });
    const baseline = memberInspection(pe, externalPdb(pdb));
    const rowOffset = baseline.debug_map?.documents[0]?.row_offset;
    expect(rowOffset).toBeTypeOf("number");
    const corrupted = Buffer.from(pdb);
    // Column order name/algorithm/hash/language: the language GUID index sits
    // at +6 and 0x4000 selects a GUID row far beyond the heap.
    corrupted.writeUInt16LE(0x4000, (rowOffset ?? 0) + 6);
    const result = memberInspection(pe, externalPdb(corrupted));
    const document = result.debug_map?.documents[0];
    expect(document?.language_guid).toBeNull();
    expect(document?.language).toBeNull();
    expect(document?.hash_algorithm).toBe("sha-384");
    expect(document?.name).toBe("/src/Program.cs");
    expect(document?.hash).not.toBeNull();
    expect(
      result.debug_map?.coverage.issues.some(
        (issue) =>
          issue.code === "invalid-guid" && issue.detail.includes("0x30000001"),
      ),
    ).toBe(true);
  });
});

describe("Portable PDB sequence-point encoding edge cases", () => {
  it("decodes ECMA-335 signed compressed line and column deltas", () => {
    // Known-answer bytes: localSig 1; p1 il=0 ΔLines=2 ΔColumns=-2 (0x7d)
    // startLine=10 startColumn=5; p2 δil=6 ΔLines=0 ΔColumns=5 startLine
    // delta -2 (0x7d) startColumn delta -3 (0x7b).
    const sequencePoints = Buffer.from([
      0x01, 0x00, 0x02, 0x7d, 0x0a, 0x05, 0x06, 0x00, 0x05, 0x7d, 0x7b,
    ]);
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      referencedStandaloneSignatures: 1,
      methods: [{ document: 1, sequencePoints }],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    const method = result.debug_map?.methods[0];
    expect(method?.state).toBe("decoded");
    expect(method?.local_signature_token).toBe("0x11000001");
    expect(method?.sequence_points).toEqual([
      {
        il_offset: 0,
        start_line: 10,
        start_column: 5,
        end_line: 12,
        end_column: 3,
        hidden: false,
        document_token: "0x30000001",
      },
      {
        il_offset: 6,
        start_line: 8,
        start_column: 2,
        end_line: 8,
        end_column: 7,
        hidden: false,
        document_token: "0x30000001",
      },
    ]);
  });

  it("rejects a mid-blob document record naming a row outside the table", () => {
    const sequencePoints = Buffer.from([
      0x01, 0x00, 0x02, 0x7d, 0x0a, 0x05, 0x00, 0x09,
    ]);
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      referencedStandaloneSignatures: 1,
      methods: [{ document: 1, sequencePoints }],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.methods[0]?.state).toBe("malformed");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("beyond the 1-row Document table"),
      ),
    ).toBe(true);
  });

  it("flags a compressed integer reserved prefix as malformed", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      referencedStandaloneSignatures: 1,
      methods: [
        { document: 1, sequencePoints: Buffer.from([0x01, 0xe0, 0x00]) },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.methods[0]?.state).toBe("malformed");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("reserved prefix"),
      ),
    ).toBe(true);
  });

  it("reports an entry-point mismatch as identity evidence", () => {
    const pdb = buildPortablePdbFixture({
      entryPointToken: 0x0600_0009,
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.identity.status).toBe("matched");
    expect(result.debug_map?.identity.checks).toContainEqual(
      expect.objectContaining({ name: "entry-point", result: "mismatched" }),
    );
  });

  it("marks an embedded payload that is not a Portable PDB as malformed", () => {
    const result = memberInspection(
      buildManagedPeFixture({
        codeview: matchingCodeview,
        embeddedPortablePdb: Buffer.from("not a pdb at all"),
      }),
      { kind: "embedded" },
    );
    expect(result.debug_map?.status).toBe("malformed");
    expect(
      result.debug_map?.coverage.issues.some((issue) =>
        issue.detail.includes("not BSJB"),
      ),
    ).toBe(true);
  });

  it("marks a truncated Portable PDB root as malformed", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [
        { document: 1, points: [{ il: 0, startLine: 1, startColumn: 1 }] },
      ],
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb.subarray(0, 40)),
    );
    expect(result.debug_map?.status).toBe("malformed");
  });

  it("counts methods outside the admitted MDI rows without stub entries", () => {
    const pdb = buildPortablePdbFixture({
      documents: [{ name: "/src/Program.cs" }],
      methods: [],
      methodDefRows: 0,
      referencedMethodDefs: 1,
    });
    const result = memberInspection(
      buildManagedPeFixture({ codeview: matchingCodeview }),
      externalPdb(pdb),
    );
    expect(result.debug_map?.methods).toEqual([]);
    expect(result.debug_map?.methods_without_debug_information).toBe(1);
  });
});
