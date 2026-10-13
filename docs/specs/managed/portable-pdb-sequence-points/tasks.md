# Tasks

- [x] Expose the PE debug directory on `ManagedPeLayout` and parse CodeView
      `RSDS` / `MPDB` entries in `ManagedDebugDirectory.ts`.
- [x] Parse Portable PDB roots, `#Pdb` identity and debug tables in
      `PortablePdbLayout.ts`; project documents and sequence points in
      `PortablePdbDebugMap.ts`.
- [x] Accept `pdb_path` / `pdb_embedded` on `inspect_managed_members` with
      provenance-preserving reads, cancellation and cleanup reuse.
- [x] Extend the fixture builder to synthesize matching PE/PDB pairs,
      mismatched stamps, embedded `MPDB` entries and malformed inputs.
- [x] Cover acceptance cases in unit, provider-boundary and CLI/MCP parity
      tests; document the selectors in `docs/managed-code-analysis.md`.
- [x] Record verified coverage for the PR linked to issue #2351.
