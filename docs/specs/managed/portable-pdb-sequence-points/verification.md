# Verification

- `npm run test:focused -- src/dotnet/PortablePdbDebugMap.test.ts tests/boundary/providers/managed/managedPortablePdb.test.ts tests/boundary/mcp/managedMcp.test.ts tests/acceptance/managedCliOutput.test.ts`
- `npm run test:local -- src/dotnet/ManagedMemberInspector.test.ts src/dotnet/ManagedArtifactInspector.test.ts src/dotnet/ManagedArtifactFailures.test.ts`
- `npm run verify:test-discovery`
- `npm run check:fast`
- `npm run docs:check`

Coverage notes:

- Synthetic fixture pairs verify a matching Portable PDB end-to-end through
  the provider, CLI and MCP input paths, including selector-conflict and
  missing-PDB input failures on both adapters.
- Mismatch, absent declaration, embedded extraction, truncation, cancellation
  and oversized-representation cases are covered without provider tooling or
  network access.
- Sequence-point encoding is verified with known-answer compressed-integer
  bytes, including signed line/column deltas, hidden points, document switches
  and reserved prefixes.
- Real-world PDB diversity (unusual document-name separators, all checksum
  algorithms) is represented by the documented GUID/encoding table rather
  than proprietary fixtures.
