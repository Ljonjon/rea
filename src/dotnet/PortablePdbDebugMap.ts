import type {
  ManagedParseIssue,
  PortablePdbDebugMap,
} from "../domain/managed/managedArtifact.js";

import {
  extractEmbeddedPortablePdb,
  readManagedDebugDirectory,
  type ManagedDebugDeclaration,
} from "./ManagedDebugDirectory.js";
import {
  admitManagedProjection,
  managedDecodeBudget,
  type ManagedDecodeBudget,
} from "./ManagedDecodeBudget.js";
import {
  metadataRowCursor,
  metadataToken,
  readMetadataBlob,
  readMetadataGuid,
  sha256Bytes,
} from "./ManagedMetadataHeaps.js";
import type { ManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import type { ManagedPeLayout } from "./ManagedPeReader.js";
import {
  portablePdbIdParts,
  readPortablePdbLayout,
  type PortablePdbLayout,
} from "./PortablePdbLayout.js";
import {
  ManagedReaderFailure,
  uniqueManagedParseIssues,
} from "./ManagedReaderFailure.js";

const DOCUMENT_TABLE = 0x30;
const METHOD_DEBUG_INFORMATION_TABLE = 0x31;
const METHOD_DEF_TABLE = 0x06;
const HIDDEN_LINE = 0xfe_efee;
/** Retained issue cap; overflow is counted and summarized, not retained. */
const MAX_DEBUG_MAP_ISSUES = 64;
/** Approximate retained projection bytes per decoded sequence point. */
const SEQUENCE_POINT_PROJECTION_BYTES = 128;

const HASH_ALGORITHMS = new Map<string, string>([
  ["ff1816ec-aa5e-4d10-87f7-6f4963833460", "sha-1"],
  ["8829d00f-11b8-4213-878b-770e8597ac16", "sha-256"],
  ["d99cfeb1-8c43-444a-8a6c-b61269d2a0bf", "sha-384"],
  ["ef2d1afc-6550-46d6-b14b-d70afe9a5566", "sha-512"],
]);

const DOCUMENT_LANGUAGES = new Map<string, string>([
  ["3f5162f8-07c6-11d3-9053-00c04fa302a1", "csharp"],
  ["3a12d0b8-c26c-11d0-b442-00a0244a1dd2", "visual-basic"],
  ["ab4f38c9-b6e6-43ba-be3b-58080b2ccce3", "fsharp"],
]);

/** Caller-selected Portable PDB evidence: external bytes or the embedded blob. */
export type PortablePdbSelection =
  | {
      readonly kind: "external";
      readonly path: string;
      readonly bytes: Buffer;
      readonly sha256: string;
    }
  | { readonly kind: "embedded" };

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Bounded per-map issue collector so hostile row counts cannot flood coverage. */
interface DebugIssueSink {
  readonly items: ManagedParseIssue[];
  omitted: number;
}

const issueSink = (): DebugIssueSink => ({ items: [], omitted: 0 });

const pushIssue = (sink: DebugIssueSink, issue: ManagedParseIssue): void => {
  if (sink.items.length < MAX_DEBUG_MAP_ISSUES) sink.items.push(issue);
  else sink.omitted += 1;
};

const malformedBlob = (
  sink: DebugIssueSink,
  detail: string,
  offset: number | null,
  scope = "pdb",
): void => {
  pushIssue(sink, { code: "invalid-blob", scope, detail, offset });
};

class BlobCursor {
  #offset = 0;
  /** Byte width of the last compressed integer read; needed for signed decode. */
  #lastWidth = 0;
  constructor(
    private readonly bytes: Buffer,
    private readonly scope: string,
  ) {}

  get offset(): number {
    return this.#offset;
  }

  get done(): boolean {
    return this.#offset >= this.bytes.length;
  }

  readUnsigned(): number {
    const first = this.#require(1)[0] ?? 0;
    if ((first & 0x80) === 0) {
      this.#offset += 1;
      this.#lastWidth = 1;
      return first;
    }
    if ((first & 0xc0) === 0x80) {
      const second = this.#require(2)[1] ?? 0;
      this.#offset += 2;
      this.#lastWidth = 2;
      return ((first & 0x3f) << 8) | second;
    }
    if ((first & 0xe0) === 0xc0) {
      const chunk = this.#require(4);
      this.#offset += 4;
      this.#lastWidth = 4;
      return (
        ((chunk[0] ?? 0) & 0x1f) * 0x01_00_00_00 +
        (chunk[1] ?? 0) * 0x01_00_00 +
        (chunk[2] ?? 0) * 0x0100 +
        (chunk[3] ?? 0)
      );
    }
    throw new BlobFormatError(
      `compressed integer uses a reserved prefix at ${this.scope} offset ${String(this.#offset)}`,
    );
  }

  /**
   * ECMA-335 II.23.2 signed compressed integers keep the sign in bit 0 and
   * the two's-complement value in bits 1..(6|13|28) depending on the encoded
   * width; decode sign-extends from that payload width.
   */
  readSigned(): number {
    const raw = this.readUnsigned();
    const payloadMask =
      this.#lastWidth === 1
        ? 0x3f
        : this.#lastWidth === 2
          ? 0x1fff
          : 0x0fffffff;
    const magnitude = raw >> 1;
    return (raw & 1) === 1 ? magnitude | ~payloadMask : magnitude;
  }

  #require(length: number): Buffer {
    if (this.#offset > this.bytes.length - length)
      throw new BlobFormatError(
        `compressed integer is truncated at ${this.scope} offset ${String(this.#offset)}`,
      );
    return this.bytes.subarray(this.#offset, this.#offset + length);
  }
}

class BlobFormatError extends Error {}

/** Decode the document name blob: UTF-8 separator then compressed blob-index parts. */
const decodeDocumentName = (
  bytes: Buffer,
  layout: PortablePdbLayout,
  blob: Buffer,
): string => {
  if (blob.length === 0) return "";
  // The separator is one UTF-8 character (1–4 bytes) or byte 0 for none.
  const first = blob[0] ?? 0;
  let separatorLength = 1;
  if (first === 0) {
    separatorLength = 1;
  } else if ((first & 0xe0) === 0xc0) separatorLength = 2;
  else if ((first & 0xf0) === 0xe0) separatorLength = 3;
  else if ((first & 0xf8) === 0xf0) separatorLength = 4;
  if (blob.length < separatorLength)
    throw new BlobFormatError("document name blob ends inside its separator");
  const separator =
    first === 0 ? "" : utf8.decode(blob.subarray(0, separatorLength));
  const cursor = new BlobCursor(
    blob.subarray(separatorLength),
    "pdb.document-name",
  );
  const parts: string[] = [];
  while (!cursor.done) {
    const partIndex = cursor.readUnsigned();
    const part = readMetadataBlob(bytes, layout, partIndex, bytes.length);
    managedDecodeBudget(layout).reserveString(part.length, null);
    parts.push(utf8.decode(part));
  }
  return parts.join(separator);
};

const decodeDocuments = (
  bytes: Buffer,
  layout: PortablePdbLayout,
  issues: DebugIssueSink,
): PortablePdbDebugMap["documents"] => {
  const table = layout.table(DOCUMENT_TABLE);
  if (table === undefined) return [];
  const documents: PortablePdbDebugMap["documents"] = [];
  for (let row = 1; row <= table.rowCount; row += 1) {
    const cursor = metadataRowCursor(bytes, layout, DOCUMENT_TABLE, row);
    const start = table.offset + (row - 1) * table.rowSize;
    const entry: PortablePdbDebugMap["documents"][number] = {
      token: metadataToken(DOCUMENT_TABLE, row),
      row_offset: start,
      name: null,
      hash_algorithm: null,
      hash_algorithm_guid: null,
      hash: null,
      language: null,
      language_guid: null,
    };
    // Each column decodes independently so one malformed cell cannot
    // suppress its readable siblings.
    const column = <T>(decode: () => T): T | null => {
      try {
        return decode();
      } catch (cause: unknown) {
        if (cause instanceof ManagedReaderFailure) {
          if (cause.issue.code === "resource-limit") throw cause;
          // Preserve the typed issue code while anchoring it to this row.
          pushIssue(issues, {
            ...cause.issue,
            detail: `Document ${entry.token}: ${cause.issue.detail}`,
          });
          return null;
        }
        throw cause;
      }
    };
    try {
      const nameIndex = cursor.readIndex(layout.blobIndexSize);
      const algorithmIndex = cursor.readIndex(layout.guidIndexSize);
      const hashIndex = cursor.readIndex(layout.blobIndexSize);
      const languageIndex = cursor.readIndex(layout.guidIndexSize);
      entry.hash_algorithm_guid = column(() =>
        readMetadataGuid(bytes, layout, algorithmIndex),
      );
      entry.hash_algorithm =
        entry.hash_algorithm_guid === null
          ? null
          : (HASH_ALGORITHMS.get(entry.hash_algorithm_guid) ?? null);
      entry.language_guid = column(() =>
        readMetadataGuid(bytes, layout, languageIndex),
      );
      entry.language =
        entry.language_guid === null
          ? null
          : (DOCUMENT_LANGUAGES.get(entry.language_guid) ?? null);
      const hashBlob = column(() =>
        readMetadataBlob(bytes, layout, hashIndex, bytes.length),
      );
      if (hashBlob !== null) {
        managedDecodeBudget(layout).reserveString(hashBlob.length * 2, start);
        entry.hash = hashBlob.length === 0 ? null : hashBlob.toString("hex");
      }
      try {
        entry.name = decodeDocumentName(
          bytes,
          layout,
          readMetadataBlob(bytes, layout, nameIndex, bytes.length),
        );
      } catch (cause: unknown) {
        if (cause instanceof ManagedReaderFailure) {
          if (cause.issue.code === "resource-limit") throw cause;
          // Preserve the typed issue code while anchoring it to this row.
          pushIssue(issues, {
            ...cause.issue,
            detail: `Document ${entry.token}: ${cause.issue.detail}`,
          });
        } else {
          malformedBlob(
            issues,
            `Document ${entry.token} name blob is malformed: ${
              cause instanceof Error ? cause.message : String(cause)
            }`,
            start,
            "pdb.Document",
          );
        }
      }
    } catch (cause: unknown) {
      if (cause instanceof ManagedReaderFailure) {
        if (cause.issue.code === "resource-limit") throw cause;
        pushIssue(issues, cause.issue);
      } else {
        throw cause;
      }
    }
    // Keep the row's identity even when a column failed to decode; sequence
    // points may still reference its document token.
    documents.push(entry);
  }
  return documents;
};

interface DecodedSequencePoint {
  readonly ilOffset: number;
  readonly documentRow: number;
  readonly startLine: number;
  readonly startColumn: number;
  readonly endLine: number;
  readonly endColumn: number;
  readonly hidden: boolean;
}

interface DecodedSequencePoints {
  readonly localSignatureRow: number;
  readonly points: readonly DecodedSequencePoint[];
}

/** Decode one sequence-points blob per the Portable PDB delta encoding. */
const decodeSequencePoints = (
  blob: Buffer,
  declaredDocumentRow: number,
  documentRowCount: number,
  budget: ManagedDecodeBudget,
): DecodedSequencePoints => {
  const cursor = new BlobCursor(blob, "pdb.sequence-points");
  const localSignatureRow = cursor.readUnsigned();
  let currentDocument = declaredDocumentRow;
  if (declaredDocumentRow === 0) currentDocument = cursor.readUnsigned();
  const points: DecodedSequencePoint[] = [];
  let ilOffset = 0;
  let previousStartLine = 0;
  let previousStartColumn = 0;
  let haveNonHidden = false;
  let first = true;
  while (!cursor.done) {
    budget.reserve(SEQUENCE_POINT_PROJECTION_BYTES, null);
    const ilDelta = cursor.readUnsigned();
    if (!first && ilDelta === 0) {
      const documentRow = cursor.readUnsigned();
      if (documentRow < 1 || documentRow > documentRowCount)
        throw new BlobFormatError(
          `document record selects row ${String(documentRow)} beyond the ${String(documentRowCount)}-row Document table`,
        );
      currentDocument = documentRow;
      continue;
    }
    ilOffset = first ? ilDelta : ilOffset + ilDelta;
    first = false;
    const lineDelta = cursor.readUnsigned();
    if (lineDelta === 0) {
      const columnDelta = cursor.readUnsigned();
      if (columnDelta === 0) {
        points.push({
          ilOffset,
          documentRow: currentDocument,
          startLine: HIDDEN_LINE,
          startColumn: 0,
          endLine: HIDDEN_LINE,
          endColumn: 0,
          hidden: true,
        });
        continue;
      }
      const startLine = haveNonHidden
        ? previousStartLine + cursor.readSigned()
        : cursor.readUnsigned();
      const startColumn = haveNonHidden
        ? previousStartColumn + cursor.readSigned()
        : cursor.readUnsigned();
      points.push({
        ilOffset,
        documentRow: currentDocument,
        startLine,
        startColumn,
        endLine: startLine,
        endColumn: startColumn + columnDelta,
        hidden: false,
      });
      previousStartLine = startLine;
      previousStartColumn = startColumn;
      haveNonHidden = true;
      continue;
    }
    const columnDelta = cursor.readSigned();
    const startLine = haveNonHidden
      ? previousStartLine + cursor.readSigned()
      : cursor.readUnsigned();
    const startColumn = haveNonHidden
      ? previousStartColumn + cursor.readSigned()
      : cursor.readUnsigned();
    points.push({
      ilOffset,
      documentRow: currentDocument,
      startLine,
      startColumn,
      endLine: startLine + lineDelta,
      endColumn: startColumn + columnDelta,
      hidden: false,
    });
    previousStartLine = startLine;
    previousStartColumn = startColumn;
    haveNonHidden = true;
  }
  return { localSignatureRow, points };
};

const validatePoint = (
  point: DecodedSequencePoint,
  previousIlOffset: number | null,
): string | null => {
  // IL offsets must stay in range and ordered even for hidden points; only
  // source-line and column constraints are non-hidden per the format spec.
  if (point.ilOffset >= 0x2000_0000)
    return `IL offset ${String(point.ilOffset)} exceeds 0x20000000`;
  if (previousIlOffset !== null && point.ilOffset <= previousIlOffset)
    return `IL offset ${String(point.ilOffset)} is not increasing`;
  if (point.hidden) return null;
  for (const [label, value] of [
    ["start line", point.startLine],
    ["end line", point.endLine],
  ] as const) {
    if (value < 0 || value >= 0x2000_0000 || value === HIDDEN_LINE)
      return `${label} ${String(value)} is outside the admitted range`;
  }
  if (
    point.startColumn < 0 ||
    point.startColumn >= 0x1_0000 ||
    point.endColumn < 0 ||
    point.endColumn >= 0x1_0000
  )
    return `column is outside the admitted 0..0xffff range`;
  if (point.endLine < point.startLine) return "end line precedes start line";
  if (point.endLine === point.startLine && point.endColumn <= point.startColumn)
    return "end column does not advance past start column on one line";
  return null;
};

const decodeMethodDebugInformation = (
  bytes: Buffer,
  layout: PortablePdbLayout,
  methodRows: readonly number[],
  issues: DebugIssueSink,
): {
  readonly methods: PortablePdbDebugMap["methods"];
  readonly uncovered: number;
} => {
  const table = layout.table(METHOD_DEBUG_INFORMATION_TABLE);
  const documentRowCount = layout.table(DOCUMENT_TABLE)?.rowCount ?? 0;
  const declaredMethodRows = layout.typeSystemRowCounts[METHOD_DEF_TABLE] ?? 0;
  if (
    table !== undefined &&
    declaredMethodRows !== 0 &&
    table.rowCount !== declaredMethodRows
  )
    pushIssue(issues, {
      code: "invalid-tables",
      scope: "pdb.MethodDebugInformation",
      detail: `MethodDebugInformation has ${String(table.rowCount)} rows but the #Pdb stream declares ${String(declaredMethodRows)} MethodDef rows`,
      offset: table.offset,
    });
  const methods: PortablePdbDebugMap["methods"] = [];
  let uncovered = 0;
  for (const row of methodRows) {
    // Rows outside the admitted MethodDebugInformation table carry no PDB
    // evidence; count them instead of emitting identical stub entries.
    if (table === undefined || row > table.rowCount || row < 1) {
      uncovered += 1;
      continue;
    }
    const token = metadataToken(METHOD_DEF_TABLE, row);
    const entry: PortablePdbDebugMap["methods"][number] = {
      token,
      state: "no-debug-information",
      document_token: null,
      local_signature_token: null,
      sequence_points: [],
    };
    const start = table.offset + (row - 1) * table.rowSize;
    try {
      const cursor = metadataRowCursor(
        bytes,
        layout,
        METHOD_DEBUG_INFORMATION_TABLE,
        row,
      );
      const documentRow = cursor.readIndex(
        layout.tableIndexSize(DOCUMENT_TABLE),
      );
      const sequenceIndex = cursor.readIndex(layout.blobIndexSize);
      if (documentRow > documentRowCount)
        throw new BlobFormatError(
          `Document column selects row ${String(documentRow)} beyond the ${String(documentRowCount)}-row Document table`,
        );
      entry.document_token =
        documentRow === 0 ? null : metadataToken(DOCUMENT_TABLE, documentRow);
      if (sequenceIndex === 0) {
        entry.state = "no-sequence-points";
        methods.push(entry);
        continue;
      }
      const blob = readMetadataBlob(bytes, layout, sequenceIndex, bytes.length);
      const decoded = decodeSequencePoints(
        blob,
        documentRow,
        documentRowCount,
        managedDecodeBudget(layout),
      );
      const standaloneSignatureRows = layout.typeSystemRowCounts[0x11] ?? 0;
      if (decoded.localSignatureRow > standaloneSignatureRows)
        throw new BlobFormatError(
          `local signature selects row ${String(decoded.localSignatureRow)} beyond the ${String(standaloneSignatureRows)} declared StandAloneSig rows`,
        );
      entry.local_signature_token =
        decoded.localSignatureRow === 0
          ? null
          : metadataToken(0x11, decoded.localSignatureRow);
      let previousIl: number | null = null;
      for (const point of decoded.points) {
        const violation = validatePoint(point, previousIl);
        if (violation !== null)
          throw new BlobFormatError(
            `sequence point at IL ${String(point.ilOffset)} is invalid: ${violation}`,
          );
        previousIl = point.ilOffset;
        if (
          point.documentRow !== 0 &&
          (point.documentRow < 1 || point.documentRow > documentRowCount)
        )
          throw new BlobFormatError(
            `sequence point at IL ${String(point.ilOffset)} inherits missing document row ${String(point.documentRow)}`,
          );
        entry.sequence_points.push({
          il_offset: point.ilOffset,
          start_line: point.startLine,
          start_column: point.startColumn,
          end_line: point.endLine,
          end_column: point.endColumn,
          hidden: point.hidden,
          document_token:
            point.documentRow === 0
              ? null
              : metadataToken(DOCUMENT_TABLE, point.documentRow),
        });
      }
      entry.state = "decoded";
    } catch (cause: unknown) {
      if (cause instanceof ManagedReaderFailure) {
        if (cause.issue.code === "resource-limit") throw cause;
        pushIssue(issues, cause.issue);
        entry.state = "malformed";
      } else if (cause instanceof BlobFormatError) {
        malformedBlob(
          issues,
          `MethodDebugInformation row ${String(row)}: ${cause.message}`,
          start,
          "pdb.MethodDebugInformation",
        );
        entry.state = "malformed";
      } else {
        throw cause;
      }
    }
    methods.push(entry);
  }
  return { methods, uncovered };
};

const debugIssues = (sink: DebugIssueSink): PortablePdbDebugMap["coverage"] => {
  const retained = uniqueManagedParseIssues(sink.items);
  const issues: ManagedParseIssue[] = [...retained];
  if (sink.omitted > 0)
    issues.push({
      code: "invalid-tables",
      scope: "pdb",
      detail: `${String(sink.omitted)} further Portable PDB issue(s) were omitted by the retained-issue bound`,
      offset: null,
    });
  return { state: issues.length === 0 ? "complete" : "partial", issues };
};

const declaredIdentity = (
  declaration: ManagedDebugDeclaration,
): PortablePdbDebugMap["identity"]["declared"] => ({
  codeview:
    declaration.codeview === null || declaration.codeview.kind !== "rsds"
      ? null
      : {
          guid: declaration.codeview.guid,
          age: declaration.codeview.age,
          stamp: declaration.codeview.stamp,
          declared_path: declaration.codeview.declaredPath,
        },
  embedded_portable_pdb: declaration.embeddedPortablePdb !== null,
});

/**
 * Bind a selected Portable PDB to the assembly: declared debug identity,
 * documents, and sequence points keyed to build-local MethodDef tokens.
 */
export const buildPortablePdbDebugMap = ({
  bytes,
  pe,
  assemblyLayout,
  methodRows,
  selection,
}: {
  readonly bytes: Buffer;
  readonly pe: ManagedPeLayout;
  readonly assemblyLayout: ManagedMetadataLayout;
  readonly methodRows: readonly number[];
  readonly selection: PortablePdbSelection;
}): PortablePdbDebugMap => {
  const issues = issueSink();
  const declaration = readManagedDebugDirectory(bytes, pe);
  for (const issue of declaration.issues) pushIssue(issues, issue);
  issues.omitted += declaration.omitted;
  if (pe.debugIssue !== null) pushIssue(issues, pe.debugIssue);
  const declared = declaredIdentity(declaration);
  // A degraded declaration — the directory slot, its enumeration, or an
  // unreadable PDB-declaring entry — means the debug identity is unknown,
  // not absent. Failures on unrelated entry types leave it intact.
  const identityUnknown = pe.debugIssue !== null || declaration.degraded;

  let pdbBytes: Buffer;
  let source: PortablePdbDebugMap["source"];
  if (selection.kind === "embedded") {
    if (declaration.embeddedPortablePdb === null)
      return {
        status: identityUnknown ? "malformed" : "absent",
        source: {
          kind: "embedded",
          path: null,
          sha256: null,
          byte_length: null,
        },
        pdb: null,
        identity: { status: "unverifiable", declared, checks: [] },
        documents: [],
        methods: [],
        methods_without_debug_information: null,
        coverage: debugIssues(issues),
      };
    const extracted = extractEmbeddedPortablePdb(
      bytes,
      declaration.embeddedPortablePdb,
      (issue) => pushIssue(issues, issue),
    );
    if (extracted === null)
      return {
        status: "malformed",
        source: {
          kind: "embedded",
          path: null,
          sha256: null,
          byte_length: null,
        },
        pdb: null,
        identity: { status: "unverifiable", declared, checks: [] },
        documents: [],
        methods: [],
        methods_without_debug_information: null,
        coverage: debugIssues(issues),
      };
    pdbBytes = extracted;
    source = {
      kind: "embedded",
      path: null,
      sha256: sha256Bytes(pdbBytes),
      byte_length: pdbBytes.length,
    };
  } else {
    pdbBytes = selection.bytes;
    source = {
      kind: "external",
      path: selection.path,
      sha256: selection.sha256,
      byte_length: pdbBytes.length,
    };
  }

  let layout: PortablePdbLayout;
  try {
    layout = readPortablePdbLayout(pdbBytes);
  } catch (cause: unknown) {
    if (cause instanceof ManagedReaderFailure) {
      pushIssue(issues, cause.issue);
      return {
        status: "malformed",
        source,
        pdb: null,
        identity: { status: "unverifiable", declared, checks: [] },
        documents: [],
        methods: [],
        methods_without_debug_information: null,
        coverage: debugIssues(issues),
      };
    }
    throw cause;
  }

  const { guid, stamp } = portablePdbIdParts(layout.pdbId);
  const checks: PortablePdbDebugMap["identity"]["checks"] = [];
  let identityStatus: PortablePdbDebugMap["identity"]["status"];
  if (declared.codeview === null) {
    identityStatus = identityUnknown ? "unverifiable" : "undeclared";
  } else {
    // Portable PDB identity is the 16-byte Guid plus the debug-directory
    // entry's TimeDateStamp, not the RSDS age (which is 1 by spec).
    const matched =
      declared.codeview.guid === guid && declared.codeview.stamp === stamp;
    identityStatus = matched ? "matched" : "mismatched";
    checks.push({
      name: "rsds-stamp",
      result: matched ? "matched" : "mismatched",
      detail: matched
        ? "CodeView RSDS GUID and entry TimeDateStamp equal the #Pdb stream PDB ID."
        : `CodeView declares GUID ${declared.codeview.guid ?? "?"} TimeDateStamp ${String(declared.codeview.stamp ?? -1)}; the PDB declares ${guid} stamp ${String(stamp)}.`,
    });
  }
  if (layout.entryPointToken !== 0 && pe.cli !== null) {
    checks.push({
      name: "entry-point",
      result:
        layout.entryPointToken === pe.cli.entryPoint ? "matched" : "mismatched",
      detail:
        layout.entryPointToken === pe.cli.entryPoint
          ? "The #Pdb entry point equals the CLI header entry point."
          : `The #Pdb entry point 0x${layout.entryPointToken.toString(16).padStart(8, "0")} differs from the CLI header entry point 0x${pe.cli.entryPoint.toString(16).padStart(8, "0")}.`,
    });
  }
  const declaredMethodRows = layout.typeSystemRowCounts[METHOD_DEF_TABLE] ?? 0;
  const observedMethodRows = assemblyLayout.rowCounts[METHOD_DEF_TABLE] ?? 0;
  if (declaredMethodRows !== 0 && observedMethodRows !== 0) {
    checks.push({
      name: "methoddef-rows",
      result:
        declaredMethodRows === observedMethodRows ? "matched" : "mismatched",
      detail:
        declaredMethodRows === observedMethodRows
          ? "The PDB declares the same MethodDef row count as the assembly metadata."
          : `The PDB declares ${String(declaredMethodRows)} MethodDef rows but the assembly has ${String(observedMethodRows)}.`,
    });
  }

  const pdbFacts = {
    stamp: layout.pdbId.toString("hex"),
    guid,
    stamp_age: stamp,
    entry_point_token:
      layout.entryPointToken === 0
        ? null
        : `0x${layout.entryPointToken.toString(16).padStart(8, "0")}`,
    version: layout.version,
  };
  try {
    const documents = decodeDocuments(pdbBytes, layout, issues);
    const decoded = decodeMethodDebugInformation(
      pdbBytes,
      layout,
      methodRows,
      issues,
    );
    // Admit the map against the PDB's own budget so an oversized well-formed
    // map degrades debug_map instead of discarding member evidence.
    return admitManagedProjection(
      {
        status: "bound",
        source,
        pdb: pdbFacts,
        identity: { status: identityStatus, declared, checks },
        documents,
        methods: decoded.methods,
        methods_without_debug_information: decoded.uncovered,
        coverage: debugIssues(issues),
      },
      managedDecodeBudget(layout),
    );
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedReaderFailure)) throw cause;
    // Decode or admission failed after identity was resolved; keep the
    // source and declaration facts instead of reporting them absent.
    pushIssue(issues, cause.issue);
    return {
      status: "malformed",
      source,
      pdb: pdbFacts,
      identity: { status: identityStatus, declared, checks },
      documents: [],
      methods: [],
      methods_without_debug_information: null,
      coverage: debugIssues(issues),
    };
  }
};
