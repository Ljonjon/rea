# Implementation plan

Add a bounded Portable PDB layer under `src/dotnet/`:

- `ManagedPeReader.ts`: expose PE data directory 6 (debug) on
  `ManagedPeLayout` so debug evidence comes through the same checked RVA map.
- `ManagedDebugDirectory.ts`: enumerate IMAGE_DEBUG_DIRECTORY entries; parse
  CodeView `RSDS` (GUID + age + declared path) keeping the entry
  `TimeDateStamp` separately — with the GUID it forms the portable PDB ID —
  and extract `MPDB` embedded Portable PDBs (`zlib.inflateRawSync` — .NET
  `DeflateStream` emits raw RFC 1951 deflate — bounded by declared size +
  snapshot cap).
- `PortablePdbLayout.ts`: parse the `BSJB` metadata root, `#Pdb` stream
  (20-byte stamp, entry-point MethodDef token, referenced type-system row
  counts) and the debug table layout (0x30–0x37) sized by those row counts.
- `PortablePdbDebugMap.ts`: project documents (name-blob reassembly, hash
  algorithm/language GUIDs, checksum bytes) and MethodDebugInformation rows
  onto MethodDef tokens; decode sequence-point blobs per the delta encoding;
  compute identity status (matched / mismatched / undeclared / unverifiable)
  from stamp, entry-point, and MethodDef row-count evidence. The PDB decode
  charges its own representation budget so an oversized map degrades
  `debug_map` to `malformed` without discarding member evidence; rows the PDB
  does not cover are counted in `methods_without_debug_information` instead
  of emitting identical stubs, and retained issues are bounded with an
  omitted count.

Wire through `inspectManagedMembersBytes` (a `pdb` selection carrying bytes +
provenance), `ManagedStaticProvider` (`pdb_path` read via `readManagedSnapshot`
with cancellation + cleanup; `pdb_embedded` from the PE image), the managed
input contract, the CLI (`--pdb`, `--pdb-embedded`), and the docs.

Extend `ManagedPe.fixture.ts` to emit a synthetic PE with a debug directory
plus a matching Portable PDB fixture so every acceptance case runs offline.
Run focused managed tests, boundary/MCP/CLI parity tests, and `check:fast`.

Primary format reference:
https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
