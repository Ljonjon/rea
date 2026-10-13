import {
  admitManagedProjection,
  managedDecodeBudget,
} from "./ManagedDecodeBudget.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  managedMemberInspectionSchema,
  type ManagedMemberInspection,
  type ManagedParseIssue,
} from "../domain/managed/managedArtifact.js";
import {
  readManagedPeLayout,
  type ManagedPeLayout,
} from "./ManagedPeReader.js";
import {
  readManagedResourceDirectory,
  managedTableRowCounts,
  readManagedMetadataInventory,
} from "./ManagedMetadataInventory.js";
import { readManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import {
  ManagedReaderFailure,
  uniqueManagedParseIssues,
} from "./ManagedReaderFailure.js";
import {
  parseTypes,
  typeRanges,
  type TypeRange,
} from "./ManagedMemberInspectorCore.js";
import {
  edges,
  parseExportedTypes,
  parseFields,
  parseMemberRefs,
  parseMethods,
  type SelectedTypeTokens,
} from "./ManagedMemberRows.js";
import type { ManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import {
  buildPortablePdbDebugMap,
  type PortablePdbSelection,
} from "./PortablePdbDebugMap.js";

const unavailable = (
  target: BinaryTarget,
  bytes: Buffer,
  issue: ManagedParseIssue | null,
  typeNames: readonly string[] | undefined,
): ManagedMemberInspection =>
  managedMemberInspectionSchema.parse(
    admitManagedProjection({
      artifact: {
        path: target.path,
        sha256: target.sha256,
        byte_length: bytes.length,
        format: "pe",
      },
      module: null,
      metadata: {
        status:
          issue === null
            ? "absent"
            : issue.code === "resource-limit"
              ? "partial"
              : "malformed",
        version: null,
        table_row_counts: {},
      },
      identity_scope: {
        token_identity: "build-local",
        requires_artifact_sha256: target.sha256,
        requires_mvid: null,
      },
      types: [],
      exported_types: null,
      fields: [],
      methods: [],
      member_refs: [],
      call_edges: [],
      field_accesses: [],
      // Nothing was examined, so no requested name is known to be unmatched.
      selection:
        typeNames === undefined
          ? null
          : { type_names: [...typeNames], unmatched_type_names: [] },
      coverage: {
        state: "unavailable",
        issues: issue === null ? [] : [issue],
      },
      limitations: [
        issue === null
          ? "The PE has no admitted CLI metadata; managed member inspection is unavailable."
          : "The CLI metadata could not be admitted; managed member inspection is unavailable.",
      ],
    }),
  );

const readMemberInventory = (
  bytes: Buffer,
  pe: ManagedPeLayout,
  issues: ManagedParseIssue[],
) => {
  const cli = pe.cli;
  if (cli === null)
    throw new TypeError("Managed inventory requires CLI metadata");
  const rootOffset = pe.rvaToOffset(
    cli.metadata.rva,
    cli.metadata.size,
    "cli.metadata",
  );
  const layout = readManagedMetadataLayout(
    bytes,
    rootOffset,
    cli.metadata.size,
  );
  const inventory = readManagedMetadataInventory(
    bytes,
    layout,
    readManagedResourceDirectory(pe, issues),
  );
  return { layout, inventory };
};

const selectTypes = (
  ranges: readonly TypeRange[],
  typeNames: readonly string[] | undefined,
): {
  readonly tokens: SelectedTypeTokens;
  readonly selection: ManagedMemberInspection["selection"];
  readonly unreadableNames: number;
} => {
  if (typeNames === undefined)
    return { tokens: null, selection: null, unreadableNames: 0 };
  const requested = new Set(typeNames);
  const tokens = new Set<string>();
  const matched = new Set<string>();
  for (const range of ranges) {
    if (range.fullName === null || !requested.has(range.fullName)) continue;
    tokens.add(range.token);
    matched.add(range.fullName);
  }
  return {
    tokens,
    unreadableNames: ranges.filter(({ fullName }) => fullName === null).length,
    selection: {
      type_names: [...typeNames],
      unmatched_type_names: typeNames.filter((name) => !matched.has(name)),
    },
  };
};

/**
 * Inspect metadata members and method bodies without loading target code.
 * Selected type names restrict full decoding to members of those exact types.
 */
export const inspectManagedMembersBytes = (
  bytes: Buffer,
  target: BinaryTarget,
  {
    typeNames,
    pdb,
  }: {
    readonly typeNames?: readonly string[];
    readonly pdb?: PortablePdbSelection;
  } = {},
): ManagedMemberInspection => {
  const pe = readManagedPeLayout(bytes);
  if (pe.cli === null)
    return unavailable(target, bytes, pe.cliIssue, typeNames);
  const issues: ManagedParseIssue[] = [];
  try {
    const { layout, inventory } = readMemberInventory(bytes, pe, issues);
    issues.push(...inventory.issues);
    const ranges = typeRanges(bytes, layout, issues);
    const {
      tokens: selected,
      selection,
      unreadableNames,
    } = selectTypes(ranges, typeNames);
    const parsedTypes = parseTypes(bytes, layout, ranges);
    issues.push(...parsedTypes.issues);
    const exportedTypes = parseExportedTypes(bytes, layout);
    issues.push(...exportedTypes.issues);
    const fields = parseFields(bytes, layout, ranges, selected);
    const memberRefs = parseMemberRefs(bytes, layout);
    issues.push(...memberRefs.issues);
    const methods = parseMethods({
      bytes,
      layout,
      pe,
      ranges,
      selected,
    });
    issues.push(...fields.issues, ...methods.issues);
    const coverageIssues = uniqueManagedParseIssues(issues);
    const incompleteMembers =
      [...fields.fields, ...memberRefs.refs, ...methods.methods].some(
        (member) => member.signature.parse_status !== "decoded",
      ) ||
      methods.methods.some(
        (method) =>
          method.body.status === "partial" ||
          method.body.status === "malformed",
      );
    const related = edges(
      methods.methods,
      methods.core,
      fields.core,
      memberRefs.core,
      managedDecodeBudget(layout),
    );
    const debugMap = bindDebugMapSafely(bytes, pe, layout, methods, pdb);
    // debug_map is admitted against the PDB layout's own budget inside
    // bindDebugMapSafely; charging it here too would let an oversized map
    // discard member evidence.
    const admitted = admitManagedProjection(
      {
        artifact: {
          path: target.path,
          sha256: target.sha256,
          byte_length: bytes.length,
          format: "pe",
        },
        module: inventory.module,
        metadata: {
          status: issues.length === 0 ? "complete" : "partial",
          version: layout.version,
          table_row_counts: managedTableRowCounts(layout),
        },
        identity_scope: {
          token_identity: "build-local",
          requires_artifact_sha256: target.sha256,
          requires_mvid: inventory.module?.mvid ?? null,
        },
        types:
          selected === null
            ? parsedTypes.types
            : parsedTypes.types.filter((type) => selected.has(type.token)),
        exported_types: exportedTypes.exportedTypes,
        fields: fields.fields,
        methods: methods.methods,
        member_refs: memberRefs.refs,
        call_edges: related.callEdges,
        field_accesses: related.fieldAccesses,
        selection,
        coverage: {
          state:
            issues.length === 0 && !incompleteMembers ? "complete" : "partial",
          issues: coverageIssues,
        },
        limitations: [
          "Metadata tokens are build-local coordinates and are only meaningful with the reported artifact SHA-256 and MVID.",
          "CIL instruction anchors are decoded from file-backed method bodies only; no target assembly is loaded or executed.",
          "Exported types are reported from ExportedType rows as declared; forwarded types are not resolved in their implementing assemblies.",
          "Member signatures decode ECMA-335 primitive, class, valuetype, generic instantiation, generic variable, pointer, byref, single-dimension and general array, function pointer, custom modifier, and typed reference forms; class and valuetype operands keep their encoded TypeDefOrRefOrSpec values, and unsupported forms such as vararg sentinels retain raw signature hashes.",
          ...(selection === null
            ? []
            : [
                "Types, fields, methods, call edges, and field accesses cover only the selected declaring types; coverage describes that selection. Edge targets outside it keep their names but are not described.",
              ]),
          ...(unreadableNames === 0
            ? []
            : [
                `${String(unreadableNames)} TypeDef name(s) could not be read; a name in selection.unmatched_type_names may belong to one of them, so its absence is not observed.`,
              ]),
          ...(debugMap === null
            ? []
            : [
                "debug_map binds the selected Portable PDB to build-local MethodDef tokens; document names and paths are reported exactly as recorded and no source content is fetched.",
                ...(debugMap.identity.status === "mismatched"
                  ? [
                      "The selected Portable PDB does not share the assembly's declared CodeView identity; sequence points describe a different build.",
                    ]
                  : []),
              ]),
        ],
      },
      managedDecodeBudget(layout),
    );
    return managedMemberInspectionSchema.parse({
      ...admitted,
      debug_map: debugMap,
    });
  } catch (cause: unknown) {
    if (cause instanceof ManagedReaderFailure)
      return unavailable(target, bytes, cause.issue, typeNames);
    throw cause;
  }
};

/**
 * A malformed Portable PDB must not discard admitted member evidence; keep its
 * failure inside debug_map instead of the member inspection coverage.
 */
const bindDebugMapSafely = (
  bytes: Buffer,
  pe: ManagedPeLayout,
  assemblyLayout: ManagedMetadataLayout,
  methods: { readonly methods: readonly { readonly token: string }[] },
  pdb: PortablePdbSelection | undefined,
): ManagedMemberInspection["debug_map"] => {
  if (pdb === undefined) return null;
  try {
    return buildPortablePdbDebugMap({
      bytes,
      pe,
      assemblyLayout,
      methodRows: methods.methods.map(
        (method) => Number.parseInt(method.token, 16) & 0xff_ffff,
      ),
      selection: pdb,
    });
  } catch (cause: unknown) {
    if (!(cause instanceof ManagedReaderFailure)) throw cause;
    return {
      status: "malformed",
      source:
        pdb.kind === "external"
          ? {
              kind: "external",
              path: pdb.path,
              sha256: pdb.sha256,
              byte_length: pdb.bytes.length,
            }
          : { kind: "embedded", path: null, sha256: null, byte_length: null },
      pdb: null,
      identity: {
        status: "unverifiable",
        declared: {
          codeview: null,
          embedded_portable_pdb: pdb.kind === "embedded",
        },
        checks: [],
      },
      documents: [],
      methods: [],
      methods_without_debug_information: null,
      coverage: { state: "partial", issues: [cause.issue] },
    };
  }
};
