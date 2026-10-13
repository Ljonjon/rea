# Portable PDB sequence points bound to managed methods

Issue: https://github.com/morluto/rea/issues/2351

## Problem and requirements

`inspect_managed_members` already admits MethodDef tokens, signatures and CIL
bodies, but cannot tell an analyst where the compiler mapped each method into
source. Portable PDBs declare that mapping, yet nothing in the managed static
lane reads them, and nothing verifies that a supplied `.pdb` actually belongs
to the selected assembly.

Accept an explicitly selected Portable PDB — either an external `.pdb` path or
the embedded `MPDB` debug-directory entry — and bind it to the selected
assembly. Establish the declared debug identity from the PE debug directory —
for Portable PDBs the CodeView `RSDS` GUID plus the entry's `TimeDateStamp`
(the RSDS age stays 1) — against the `#Pdb` stream's 20-byte PDB ID, keep
mismatches explicit, and emit document names with checksums plus every
visible/hidden sequence point keyed to build-local MethodDef tokens and IL
offsets.

- Keep absent documents, hidden points and unreadable tables separate.
- Preserve both artifact hashes (assembly and PDB) and source-byte provenance.
- Never fetch SourceLink content, open document paths, or execute target code.
- CLI and MCP must reach the same result through the same parameters.

## Acceptance

- `inspect_managed_members` accepts `pdb_path` and `pdb_embedded` selectors.
- A matching Portable PDB yields `debug_map` with identity `matched`, decoded
  document names, checksum algorithms/hashes, and sequence points (including
  hidden `0xFEEFEE` points and multi-document methods) keyed by method token.
- A GUID/stamp mismatch, missing or unreadable CodeView data, or non-Portable
  PDB bytes keep identity status honest (`mismatched`, `undeclared`,
  `unverifiable`) without failing the member inspection itself.
- Truncated roots, truncated sequence-point blobs, bad row indexes and bad
  heap indexes surface as coverage issues, not crashes.
- Cancellation during the external PDB read propagates and cleans up like the
  assembly snapshot path.
- `inspect-managed-members --pdb`/`--pdb-embedded` mirrors the MCP surface.

## Out of scope

Windows (MSF/C7) PDBs, SourceLink resolution, fetching or opening source
files, locals/scopes/import tables beyond what row sizing needs, decompiling
C#, executing target code, and mutating caller files.
