/** Synthetic Portable PDB builder: source-owned bytes, no compiled fixtures. */

const u16 = (value: number): Buffer => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value, 0);
  return bytes;
};

const u32 = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value, 0);
  return bytes;
};

const u64 = (value: bigint): Buffer => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(value, 0);
  return bytes;
};

const align4 = (value: number): number => Math.ceil(value / 4) * 4;

/** Unsigned ECMA-335 compressed integer. */
const compressedUnsigned = (value: number): Buffer =>
  value < 0x80
    ? Buffer.from([value])
    : value < 0x4000
      ? Buffer.from([0x80 | (value >> 8), value & 0xff])
      : Buffer.from([
          0xc0 | (value >> 24),
          (value >> 16) & 0xff,
          (value >> 8) & 0xff,
          value & 0xff,
        ]);

/**
 * Signed ECMA-335 compressed integer: bit 0 carries the sign and bits
 * 1..(6|13|28) carry the two's-complement value, so decode sign-extends
 * from the encoded width.
 */
const compressedSigned = (value: number): Buffer => {
  const sign = value < 0 ? 1 : 0;
  if (value >= -0x40 && value <= 0x3f)
    return Buffer.from([((value & 0x3f) << 1) | sign]);
  // The signed encoding keeps the branch's width: masking a negative value
  // can shrink the payload, but the signed range still selects the wider
  // form, so emit the width directly rather than re-selecting unsigned.
  if (value >= -0x2000 && value <= 0x1fff) {
    const raw = ((value & 0x1fff) << 1) | sign;
    return Buffer.from([0x80 | (raw >> 8), raw & 0xff]);
  }
  const raw = ((value & 0x0fff_ffff) << 1) | sign;
  return Buffer.from([
    0xc0 | (raw >>> 24),
    (raw >> 16) & 0xff,
    (raw >> 8) & 0xff,
    raw & 0xff,
  ]);
};

/** On-disk #GUID heap byte order (little-endian leading fields). */
export const portablePdbGuidBytes = (guid: string): Buffer => {
  const hex = guid.replaceAll("-", "");
  if (hex.length !== 32) throw new RangeError("fixture GUID must be 16 bytes");
  const raw = Buffer.from(hex, "hex");
  return Buffer.concat([
    Buffer.from([
      raw.readUInt8(3),
      raw.readUInt8(2),
      raw.readUInt8(1),
      raw.readUInt8(0),
    ]),
    Buffer.from([raw.readUInt8(5), raw.readUInt8(4)]),
    Buffer.from([raw.readUInt8(7), raw.readUInt8(6)]),
    raw.subarray(8, 16),
  ]);
};

const guidBytes = portablePdbGuidBytes;

const HASH_ALGORITHM_GUIDS: Record<string, string> = {
  "sha-1": "ff1816ec-aa5e-4d10-87f7-6f4963833460",
  "sha-256": "8829d00f-11b8-4213-878b-770e8597ac16",
  "sha-384": "d99cfeb1-8c43-444a-8a6c-b61269d2a0bf",
  "sha-512": "ef2d1afc-6550-46d6-b14b-d70afe9a5566",
};

const LANGUAGE_GUIDS: Record<string, string> = {
  csharp: "3f5162f8-07c6-11d3-9053-00c04fa302a1",
  "visual-basic": "3a12d0b8-c26c-11d0-b442-00a0244a1dd2",
  fsharp: "ab4f38c9-b6e6-43ba-be3b-58080b2ccce3",
};

class BlobHeap {
  readonly #chunks: Buffer[] = [Buffer.from([0])];
  #size = 1;

  get size(): number {
    return this.#size;
  }

  add(value: Buffer): number {
    if (value.length === 0) return 0;
    const index = this.#size;
    const prefix = compressedUnsigned(value.length);
    this.#chunks.push(prefix, value);
    this.#size += value.length + prefix.length;
    return index;
  }

  addUtf8(value: string): number {
    return this.add(Buffer.from(value, "utf8"));
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.#chunks);
  }
}

class GuidHeap {
  readonly #guids: Buffer[] = [];

  get size(): number {
    return this.#guids.length;
  }

  add(guid: string): number {
    const bytes = guidBytes(guid);
    const index = this.#guids.length + 1;
    this.#guids.push(bytes);
    return index;
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.#guids);
  }
}

export interface PortablePdbPoint {
  readonly il: number;
  readonly startLine?: number;
  readonly startColumn?: number;
  readonly endLine?: number;
  readonly endColumn?: number;
  readonly hidden?: boolean;
  /** Emit a document record before this point. */
  readonly document?: number;
}

export interface PortablePdbFixtureOptions {
  /** 20-byte #Pdb stamp: 16-byte GUID + 4-byte age stamp. */
  readonly pdbId?: Buffer;
  readonly entryPointToken?: number;
  readonly methodDefRows?: number;
  readonly documents?: readonly {
    readonly name: string;
    readonly hashAlgorithm?: string;
    readonly hash?: Buffer;
    readonly language?: string;
  }[];
  /** One MethodDebugInformation row per entry, aligned to MethodDef rows. */
  readonly methods?: readonly {
    readonly document?: number;
    /** Raw blob bytes take priority over generated points. */
    readonly sequencePoints?: Buffer;
    readonly points?: readonly PortablePdbPoint[];
    readonly localSignature?: number;
  }[];
  /** Override the referenced type-system table mask/counts. */
  readonly referencedMethodDefs?: number;
  /** Declared StandAloneSig rows; defaults to the largest localSignature used. */
  readonly referencedStandaloneSignatures?: number;
  readonly extraDocumentRows?: number;
}

const DEFAULT_PDB_ID = Buffer.concat([
  guidBytes("11111111-2222-3333-4444-555555555555"),
  u32(0x6a9b_2c4d),
]);

/** Compose the 20-byte #Pdb stamp from a dashed GUID + 32-bit age stamp. */
export const portablePdbStamp = (guid: string, stamp: number): Buffer =>
  Buffer.concat([guidBytes(guid), u32(stamp)]);

/** The default fixture stamp GUID, for matching CodeView declarations. */
export const PORTABLE_PDB_FIXTURE_GUID = "11111111-2222-3333-4444-555555555555";
/** Default #Pdb content stamp; deliberately distinct from the RSDS age (1). */
export const PORTABLE_PDB_FIXTURE_STAMP = 0x6a9b_2c4d;

/** Encode one sequence-points blob from declarative point records. */
export const portablePdbSequencePointsBlob = (
  declaredDocument: number,
  points: readonly PortablePdbPoint[],
  localSignature = 1,
): Buffer => {
  const parts: Buffer[] = [compressedUnsigned(localSignature)];
  if (declaredDocument === 0)
    parts.push(
      compressedUnsigned(
        points.find((point) => point.document !== undefined)?.document ?? 1,
      ),
    );
  let previousIl = 0;
  let previousStartLine = 0;
  let previousStartColumn = 0;
  let haveNonHidden = false;
  let first = true;
  for (const point of points) {
    if (point.document !== undefined && !first) {
      parts.push(compressedUnsigned(0), compressedUnsigned(point.document));
    }
    const il = point.il;
    parts.push(compressedUnsigned(first ? il : il - previousIl));
    previousIl = il;
    first = false;
    if (point.hidden === true) {
      parts.push(compressedUnsigned(0), compressedUnsigned(0));
      continue;
    }
    const startLine = point.startLine ?? 0;
    const startColumn = point.startColumn ?? 0;
    const endLine = point.endLine ?? startLine;
    const endColumn = point.endColumn ?? startColumn + 1;
    const lineDelta = endLine - startLine;
    parts.push(compressedUnsigned(lineDelta));
    parts.push(
      lineDelta === 0
        ? compressedUnsigned(endColumn - startColumn)
        : compressedSigned(endColumn - startColumn),
    );
    parts.push(
      haveNonHidden
        ? compressedSigned(startLine - previousStartLine)
        : compressedUnsigned(startLine),
    );
    parts.push(
      haveNonHidden
        ? compressedSigned(startColumn - previousStartColumn)
        : compressedUnsigned(startColumn),
    );
    previousStartLine = startLine;
    previousStartColumn = startColumn;
    haveNonHidden = true;
  }
  return Buffer.concat(parts);
};

/** Compose the #Pdb stream: stamp, entry point, referenced type-system rows. */
const pdbIdentityStream = (
  options: PortablePdbFixtureOptions,
  referencedMethodDefs: number,
): Buffer => {
  // Raw sequencePoints blobs hide their header localSignature; only generated
  // blobs contribute to the declared StandAloneSig count.
  const referencedStandaloneSignatures =
    options.referencedStandaloneSignatures ??
    Math.max(
      0,
      ...(options.methods ?? []).map((method) =>
        method.sequencePoints === undefined ? (method.localSignature ?? 1) : 0,
      ),
    );
  const referencedMask =
    (1n << 6n) | (referencedStandaloneSignatures > 0 ? 1n << 0x11n : 0n);
  return Buffer.concat([
    options.pdbId ?? DEFAULT_PDB_ID,
    u32(options.entryPointToken ?? 0x0600_0001),
    u64(referencedMask),
    u32(referencedMethodDefs),
    ...(referencedStandaloneSignatures > 0
      ? [u32(referencedStandaloneSignatures)]
      : []),
  ]);
};

/** Build a standalone Portable PDB with the given documents and method maps. */
export const buildPortablePdbFixture = (
  options: PortablePdbFixtureOptions = {},
): Buffer => {
  const blobs = new BlobHeap();
  const guids = new GuidHeap();
  const strings = Buffer.from([0]);
  const us = Buffer.from([0]);

  const documentCount = options.documents?.length ?? 0;
  const documentIndexes =
    options.documents?.map((document) => {
      const separator = "/";
      // Empty parts are real parts; their #Blob index is 0 (empty string).
      const parts = document.name.split("/");
      const nameBlob = Buffer.concat([
        Buffer.from(separator, "utf8"),
        ...parts.map((part) =>
          compressedUnsigned(part.length === 0 ? 0 : blobs.addUtf8(part)),
        ),
      ]);
      return {
        name: blobs.add(nameBlob),
        algorithm: guids.add(
          HASH_ALGORITHM_GUIDS[document.hashAlgorithm ?? "sha-256"] ??
            document.hashAlgorithm ??
            HASH_ALGORITHM_GUIDS["sha-256"]!,
        ),
        hash: blobs.add(
          document.hash ??
            Buffer.from(
              "0000000000000000000000000000000000000000000000000000000000000000",
              "hex",
            ),
        ),
        language: guids.add(
          LANGUAGE_GUIDS[document.language ?? "csharp"] ??
            document.language ??
            LANGUAGE_GUIDS["csharp"]!,
        ),
      };
    }) ?? [];

  const methodCount = options.methods?.length ?? 0;

  const documentRows = Buffer.concat(
    documentIndexes.map((index) =>
      Buffer.concat([
        u16(index.name),
        u16(index.algorithm),
        u16(index.hash),
        u16(index.language),
      ]),
    ),
  );
  const mdiRows = Buffer.concat(
    (options.methods ?? []).map((method) => {
      const sequenceIndex =
        method.sequencePoints !== undefined ||
        (method.points !== undefined && method.points.length > 0)
          ? blobs.add(
              method.sequencePoints ??
                portablePdbSequencePointsBlob(
                  method.document ?? 1,
                  method.points ?? [],
                  method.localSignature ?? 1,
                ),
            )
          : 0;
      return Buffer.concat([u16(method.document ?? 0), u16(sequenceIndex)]);
    }),
  );

  const referencedMethodDefs =
    options.referencedMethodDefs ?? options.methodDefRows ?? methodCount;
  const pdbStream = pdbIdentityStream(options, referencedMethodDefs);

  const hasDocuments =
    documentCount > 0 || (options.extraDocumentRows ?? 0) > 0;
  const documentTableBytes = Buffer.concat([
    documentRows,
    Buffer.alloc((options.extraDocumentRows ?? 0) * 8),
  ]);
  const validMask =
    (hasDocuments ? 1n << 0x30n : 0n) | (methodCount > 0 ? 1n << 0x31n : 0n);
  const tablesBody = Buffer.concat([
    ...(hasDocuments
      ? [u32(documentCount + (options.extraDocumentRows ?? 0))]
      : []),
    ...(methodCount > 0 ? [u32(methodCount)] : []),
    documentTableBytes,
    mdiRows,
  ]);
  // Fixture heaps stay small, so every index is two bytes.
  const tablesStream = Buffer.concat([
    Buffer.alloc(4),
    Buffer.from([1, 1]),
    Buffer.from([0, 0]),
    u64(validMask),
    u64(0n),
    tablesBody,
  ]);

  const streamParts: { name: string; data: Buffer }[] = [
    { name: "#Pdb", data: pdbStream },
    { name: "#~", data: tablesStream },
    { name: "#Strings", data: strings },
    { name: "#US", data: us },
    { name: "#GUID", data: guids.toBuffer() },
    { name: "#Blob", data: blobs.toBuffer() },
  ];
  const version = Buffer.from("PDB v1.0\0\0\0\0", "ascii");
  const headerLength =
    16 +
    version.length +
    4 +
    streamParts.reduce(
      (sum, part) => sum + 8 + align4(part.name.length + 1),
      0,
    );
  let cursor = headerLength;
  const streamHeaders = streamParts.map((part) => {
    const header = { offset: cursor, size: part.data.length, name: part.name };
    cursor += part.data.length;
    return header;
  });
  const root = Buffer.alloc(cursor);
  root.writeUInt32LE(0x424a_5342, 0);
  root.writeUInt16LE(1, 4);
  root.writeUInt16LE(1, 6);
  root.writeUInt32LE(0, 8);
  root.writeUInt32LE(version.length, 12);
  version.copy(root, 16);
  const streamsOffset = 16 + version.length;
  root.writeUInt16LE(0, streamsOffset);
  root.writeUInt16LE(streamParts.length, streamsOffset + 2);
  let headerCursor = streamsOffset + 4;
  for (const header of streamHeaders) {
    root.writeUInt32LE(header.offset, headerCursor);
    root.writeUInt32LE(header.size, headerCursor + 4);
    headerCursor += 8;
    root.write(header.name, headerCursor, "ascii");
    headerCursor += align4(header.name.length + 1);
  }
  for (const [index, part] of streamParts.entries()) {
    part.data.copy(root, streamHeaders[index]?.offset ?? 0);
  }
  return root;
};
