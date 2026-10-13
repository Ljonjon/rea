import {
  attachManagedDecodeBudget,
  ManagedDecodeBudget,
} from "./ManagedDecodeBudget.js";
import {
  CODED_INDEXES,
  type CodedIndexName,
  type ManagedMetadataLayout,
  type MetadataTableLayout,
} from "./ManagedMetadataLayout.js";
import { managedFailure } from "./ManagedReaderFailure.js";

/** Debug-table indexes admitted inside a Portable PDB tables stream. */
export const PORTABLE_PDB_TABLE_NAMES = new Map<number, string>([
  [0x30, "Document"],
  [0x31, "MethodDebugInformation"],
  [0x32, "LocalScope"],
  [0x33, "LocalVariable"],
  [0x34, "LocalConstant"],
  [0x35, "ImportScope"],
  [0x36, "StateMachineMethod"],
  [0x37, "CustomDebugInformation"],
]);

const DEBUG_TABLE_MASK = (() => {
  let mask = 0n;
  for (const index of PORTABLE_PDB_TABLE_NAMES.keys())
    mask |= 1n << BigInt(index);
  return mask;
})();

export interface PortablePdbLayout extends ManagedMetadataLayout {
  /** 20-byte id stored in the #Pdb stream: 16-byte GUID + 4-byte stamp. */
  readonly pdbId: Buffer;
  /** Entry-point MethodDef token, or 0 when the module has none. */
  readonly entryPointToken: number;
  /** Row counts the PDB declares for the referenced type-system tables. */
  readonly typeSystemRowCounts: readonly number[];
  /** File offsets of each debug table's row area. */
  readonly pdbTables: ReadonlyMap<number, MetadataTableLayout>;
}

interface MetadataStream {
  readonly name: string;
  readonly offset: number;
  readonly size: number;
}

const align4 = (value: number): number => Math.ceil(value / 4) * 4;

const requireRange = (
  bytes: Buffer,
  offset: number,
  length: number,
  scope: string,
): void => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset > bytes.length - length
  )
    throw managedFailure(
      "invalid-metadata-root",
      scope,
      `${scope} leaves the metadata byte range`,
      Number.isSafeInteger(offset) && offset >= 0 ? offset : null,
    );
};

const readStreamName = (
  bytes: Buffer,
  offset: number,
): { readonly name: string; readonly next: number } => {
  const endLimit = Math.min(bytes.length, offset + 32);
  let end = offset;
  while (end < endLimit && bytes[end] !== 0) end += 1;
  if (end === endLimit)
    throw managedFailure(
      "invalid-stream",
      "pdb.stream-name",
      "Portable PDB stream name is missing a bounded terminator",
      offset,
    );
  const nameBytes = bytes.subarray(offset, end);
  if (nameBytes.some((byte) => byte < 0x20 || byte > 0x7e))
    throw managedFailure(
      "invalid-stream",
      "pdb.stream-name",
      "Portable PDB stream name is not printable ASCII",
      offset,
    );
  return {
    name: nameBytes.toString("ascii"),
    next: align4(end + 1),
  };
};

const readStreams = (
  bytes: Buffer,
  budget: ManagedDecodeBudget,
): { streams: ReadonlyMap<string, MetadataStream>; version: string } => {
  requireRange(bytes, 0, 4, "pdb.signature");
  if (bytes.readUInt32LE(0) !== 0x424a_5342) {
    const msf = bytes
      .subarray(0, Math.min(bytes.length, 32))
      .toString("latin1");
    throw managedFailure(
      "invalid-metadata-root",
      "pdb.signature",
      msf.startsWith("Microsoft C/C++ MSF 7.00")
        ? "Artifact is a Windows (MSF) PDB, not a Portable PDB"
        : "Portable PDB metadata signature is not BSJB",
      0,
    );
  }
  requireRange(bytes, 0, 16, "pdb.root");
  const versionLength = bytes.readUInt32LE(12);
  requireRange(bytes, 16, versionLength, "pdb.version");
  const versionBytes = bytes.subarray(16, 16 + versionLength);
  const zero = versionBytes.indexOf(0);
  const decodedLength = zero < 0 ? versionBytes.length : zero;
  // Real roots carry "PDB v1.0"; a far longer string is retained verbatim in
  // debug_map, so bound it rather than echoing megabytes of padding.
  if (decodedLength > 1024)
    throw managedFailure(
      "invalid-metadata-root",
      "pdb.version",
      "Portable PDB version string exceeds the admitted bound",
      16,
    );
  budget.reserveString(decodedLength, 16);
  const version = versionBytes.subarray(0, decodedLength).toString("utf8");
  let cursor = align4(16 + versionLength);
  requireRange(bytes, cursor, 4, "pdb.stream-count");
  const streamCount = bytes.readUInt16LE(cursor + 2);
  if (streamCount === 0 || streamCount > 64)
    throw managedFailure(
      "invalid-stream",
      "pdb.stream-count",
      "Portable PDB stream count is outside the admitted range",
      cursor + 2,
    );
  cursor += 4;
  const streams = new Map<string, MetadataStream>();
  for (let index = 0; index < streamCount; index += 1) {
    requireRange(bytes, cursor, 8, "pdb.stream-header");
    const relativeOffset = bytes.readUInt32LE(cursor);
    const streamSize = bytes.readUInt32LE(cursor + 4);
    const named = readStreamName(bytes, cursor + 8);
    if (streams.has(named.name))
      throw managedFailure(
        "invalid-stream",
        "pdb.stream-header",
        `Duplicate Portable PDB stream ${named.name}`,
        cursor,
      );
    requireRange(bytes, relativeOffset, streamSize, `pdb.${named.name}`);
    streams.set(named.name, {
      name: named.name,
      offset: relativeOffset,
      size: streamSize,
    });
    cursor = named.next;
  }
  return { streams, version };
};

/** Read #Pdb: 20-byte id, u32 entry point, u64 referenced-table mask, u32 counts. */
const readPdbStream = (
  bytes: Buffer,
  stream: MetadataStream | undefined,
): {
  readonly pdbId: Buffer;
  readonly entryPointToken: number;
  readonly typeSystemRowCounts: readonly number[];
} => {
  if (stream === undefined)
    throw managedFailure(
      "missing-stream",
      "pdb.#Pdb",
      "Portable PDB does not contain its #Pdb identity stream",
    );
  const end = stream.offset + stream.size;
  if (stream.size < 32 || stream.offset + 32 > end)
    throw managedFailure(
      "invalid-stream",
      "pdb.#Pdb",
      "Portable PDB #Pdb stream is shorter than its fixed header",
      stream.offset,
    );
  const pdbId = Buffer.from(bytes.subarray(stream.offset, stream.offset + 20));
  const entryPointToken = bytes.readUInt32LE(stream.offset + 20);
  const referencedMask = bytes.readBigUInt64LE(stream.offset + 24);
  const rowCounts = Array<number>(0x2d).fill(0);
  let cursor = stream.offset + 32;
  for (let index = 0; index < 0x2d; index += 1) {
    if ((referencedMask & (1n << BigInt(index))) === 0n) continue;
    if (cursor + 4 > end)
      throw managedFailure(
        "invalid-stream",
        "pdb.#Pdb",
        "Portable PDB #Pdb row counts leave the stream extent",
        cursor,
      );
    rowCounts[index] = bytes.readUInt32LE(cursor);
    cursor += 4;
  }
  return { pdbId, entryPointToken, typeSystemRowCounts: rowCounts };
};

interface HeapSizes {
  readonly string: 2 | 4;
  readonly guid: 2 | 4;
  readonly blob: 2 | 4;
}

const tableIndex = (rows: number): 2 | 4 => (rows < 0x1_0000 ? 2 : 4);

/** HasCustomDebugInformation: 5 tag bits over 22 type-system + 5 debug tables. */
const customDebugInformationIndexSize = (
  typeRows: readonly number[],
  pdbRows: readonly number[],
): 2 | 4 => {
  const typeTables = [
    0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11,
    0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
  ];
  const debugTables = [0x30, 0x32, 0x33, 0x34, 0x35];
  let maximum = 0;
  for (const table of typeTables)
    maximum = Math.max(maximum, typeRows[table] ?? 0);
  for (const table of debugTables)
    maximum = Math.max(maximum, pdbRows[table] ?? 0);
  return maximum < 2 ** (16 - 5) ? 2 : 4;
};

const pdbTableIndexSize = (
  index: number,
  typeRows: readonly number[],
  pdbRows: readonly number[],
): 2 | 4 =>
  index >= 0x30
    ? tableIndex(pdbRows[index] ?? 0)
    : tableIndex(typeRows[index] ?? 0);

const pdbRowSize = (
  index: number,
  heaps: HeapSizes,
  typeRows: readonly number[],
  pdbRows: readonly number[],
): number => {
  const t = (table: number) => pdbTableIndexSize(table, typeRows, pdbRows);
  switch (index) {
    case 0x30: // Document: Name, HashAlgorithm, Hash, Language
      return heaps.blob + heaps.guid + heaps.blob + heaps.guid;
    case 0x31: // MethodDebugInformation: Document, SequencePoints
      return t(0x30) + heaps.blob;
    case 0x32: // LocalScope: Method, ImportScope, VariableList, ConstantList, StartOffset, Length
      return t(0x06) + t(0x35) + t(0x33) + t(0x34) + 4 + 4;
    case 0x33: // LocalVariable: Attributes, Index, Name
      return 2 + 2 + heaps.string;
    case 0x34: // LocalConstant: Name, Value
      return heaps.string + heaps.blob;
    case 0x35: // ImportScope: Parent, Imports
      return t(0x35) + heaps.blob;
    case 0x36: // StateMachineMethod: MoveNextMethod, KickoffMethod
      return t(0x06) + t(0x06);
    case 0x37: // CustomDebugInformation: Parent, Kind, Value
      return (
        customDebugInformationIndexSize(typeRows, pdbRows) +
        heaps.guid +
        heaps.blob
      );
    default:
      throw managedFailure(
        "invalid-tables",
        "pdb.tables",
        `Portable PDB table 0x${index.toString(16)} is not a debug table`,
      );
  }
};

const requireStream = (
  streams: ReadonlyMap<string, MetadataStream>,
  name: string,
): MetadataStream => {
  const stream = streams.get(name);
  if (stream === undefined)
    throw managedFailure(
      "missing-stream",
      `pdb.${name}`,
      `Required Portable PDB stream ${name} is absent`,
    );
  return stream;
};

const optionalStream = (
  streams: ReadonlyMap<string, MetadataStream>,
  name: string,
): MetadataStream => streams.get(name) ?? { name, offset: 0, size: 0 };

/** Parse a standalone Portable PDB root, #Pdb identity, and debug-table layout. */
export const readPortablePdbLayout = (bytes: Buffer): PortablePdbLayout => {
  const budget = new ManagedDecodeBudget();
  const { streams, version } = readStreams(bytes, budget);
  const pdb = readPdbStream(bytes, streams.get("#Pdb"));
  const tablesStream =
    streams.get("#~") ??
    streams.get("#-") ??
    (() => {
      throw managedFailure(
        "missing-stream",
        "pdb.tables",
        "Portable PDB does not contain its #~ or #- tables stream",
      );
    })();
  const tableBytes = bytes.subarray(
    tablesStream.offset,
    tablesStream.offset + tablesStream.size,
  );
  requireRange(tableBytes, 0, 24, "pdb.tables-header");
  const heapSizes = tableBytes[6] ?? 0;
  const heaps: HeapSizes = {
    string: (heapSizes & 0x01) === 0 ? 2 : 4,
    guid: (heapSizes & 0x02) === 0 ? 2 : 4,
    blob: (heapSizes & 0x04) === 0 ? 2 : 4,
  };
  const valid = tableBytes.readBigUInt64LE(8);
  if ((valid & ~DEBUG_TABLE_MASK) !== 0n)
    throw managedFailure(
      "invalid-tables",
      "pdb.valid-mask",
      "Portable PDB tables stream declares non-debug tables",
      tablesStream.offset + 8,
    );
  const pdbRowCounts = Array<number>(0x38).fill(0);
  let tableCursor = 24;
  for (const index of PORTABLE_PDB_TABLE_NAMES.keys()) {
    if ((valid & (1n << BigInt(index))) === 0n) continue;
    requireRange(tableBytes, tableCursor, 4, "pdb.table-row-count");
    pdbRowCounts[index] = tableBytes.readUInt32LE(tableCursor);
    tableCursor += 4;
  }
  if (((tableBytes[6] ?? 0) & 0x40) !== 0) {
    if (tableCursor > tableBytes.length - 4)
      throw managedFailure(
        "invalid-metadata-root",
        "pdb.tables-extra-data",
        "Portable PDB tables extra-data word is truncated",
        tablesStream.offset + tableCursor,
      );
    tableCursor += 4;
  }
  const pdbTables = new Map<number, MetadataTableLayout>();
  for (const [index, name] of PORTABLE_PDB_TABLE_NAMES) {
    if ((valid & (1n << BigInt(index))) === 0n) continue;
    const rowCount = pdbRowCounts[index] ?? 0;
    const rowSize = pdbRowSize(
      index,
      heaps,
      pdb.typeSystemRowCounts,
      pdbRowCounts,
    );
    const byteLength = rowCount * rowSize;
    if (!Number.isSafeInteger(byteLength))
      throw managedFailure(
        "invalid-tables",
        "pdb.tables",
        "Portable PDB table byte size overflowed",
        tablesStream.offset + tableCursor,
      );
    requireRange(tableBytes, tableCursor, byteLength, "pdb.table-data");
    pdbTables.set(index, {
      index,
      name,
      rowCount,
      rowSize,
      offset: tablesStream.offset + tableCursor,
    });
    tableCursor += byteLength;
  }
  const layout: PortablePdbLayout = {
    rootOffset: 0,
    size: bytes.length,
    version,
    streamNames: [...streams.keys()].sort(),
    strings: optionalStream(streams, "#Strings"),
    guid: optionalStream(streams, "#GUID"),
    blob: requireStream(streams, "#Blob"),
    tables: pdbTables,
    rowCounts: pdb.typeSystemRowCounts,
    stringIndexSize: heaps.string,
    guidIndexSize: heaps.guid,
    blobIndexSize: heaps.blob,
    table: (index) => pdbTables.get(index),
    tableIndexSize: (index) =>
      pdbTableIndexSize(index, pdb.typeSystemRowCounts, pdbRowCounts),
    codedIndexSize: (name: CodedIndexName) => {
      const descriptor = CODED_INDEXES[name];
      let maximum = 0;
      for (const table of descriptor.tables)
        maximum = Math.max(maximum, pdb.typeSystemRowCounts[table] ?? 0);
      return maximum < 2 ** (16 - descriptor.bits) ? 2 : 4;
    },
    pdbId: pdb.pdbId,
    entryPointToken: pdb.entryPointToken,
    typeSystemRowCounts: pdb.typeSystemRowCounts,
    pdbTables,
  };
  attachManagedDecodeBudget(layout, budget);
  return layout;
};

/** Format the 20-byte #Pdb stamp as `guid+age` matching a CodeView RSDS pair. */
export const portablePdbIdParts = (
  pdbId: Buffer,
): { readonly guid: string; readonly stamp: number } => ({
  guid:
    `${pdbId.readUInt32LE(0).toString(16).padStart(8, "0")}-` +
    `${pdbId.readUInt16LE(4).toString(16).padStart(4, "0")}-` +
    `${pdbId.readUInt16LE(6).toString(16).padStart(4, "0")}-` +
    pdbId.subarray(8, 10).toString("hex") +
    "-" +
    pdbId.subarray(10, 16).toString("hex"),
  stamp: pdbId.readUInt32LE(16),
});
