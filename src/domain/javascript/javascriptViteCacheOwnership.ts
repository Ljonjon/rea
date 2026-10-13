import * as t from "@babel/types";

import {
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import {
  collectJavaScriptIdentityWritesSteps,
  electronMemberPath,
} from "./javascriptElectronMemberWrites.js";
import { createSemanticModuleInterop } from "./javascriptModuleInterop.js";
import { semanticPropertyPathKeyMatches } from "./javascriptSemanticPropertyPaths.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
  type JavaScriptSemanticBindingState,
} from "./javascriptSemanticState.js";

type CacheTable = readonly (string | undefined)[];
type CacheKey = string | null | undefined;
type CachePath = readonly (string | null)[];
type AliasInitializer =
  JavaScriptSemanticBindingState["referenceInitializers"][number];
type AliasVertex = string | t.Node;

interface CacheOwnership {
  /** null joins different helper owners without allocating their cross-product. */
  readonly owner: string | null;
  readonly first: CacheKey;
  readonly direct: boolean;
  readonly shared: boolean;
}

interface CacheAlias {
  readonly target: AliasVertex;
  /** Selection in the source before an object-rest copy. */
  readonly sourceFirst?: CacheKey;
  /** Selection in the produced value, after any copy. */
  readonly first: CacheKey;
  /** undefined is an alias; a boolean retains the object-rest copied selection. */
  readonly copyKeepsCache?: boolean;
}

const ARRAY_MUTATORS = new Set([
  "copyWithin",
  "fill",
  "pop",
  "push",
  "reverse",
  "shift",
  "sort",
  "splice",
  "unshift",
]);

/** invalidate admitted Vite caches through possible lexical aliases and shared writes. */
export function* invalidateJavaScriptViteCachesSteps(
  program: t.Program,
  tables: Map<string, CacheTable | null>,
  initializations: ReadonlySet<t.Node | undefined>,
  state: JavaScriptSemanticAnalysisState,
): Generator<void> {
  const origins = yield* createViteCacheOriginsSteps(tables, state);
  const interop = createSemanticModuleInterop(state);
  let allOwners = false;
  const retain = (node: t.Node, path: CachePath): void => {
    const owner = path[0];
    if (initializations.has(node) || owner === undefined || allOwners) return;
    if (path.length !== 1 && path[1] !== null && path[1] !== "f") return;
    if (owner === null) allOwners = true;
    else if (tables.has(owner)) tables.set(owner, null);
  };
  yield* collectJavaScriptIdentityWritesSteps(
    program,
    (node, kind) => (kind === "member" ? origins(node) : []),
    (node) => {
      const callee = unwrapJavaScriptExpression(node.callee).node;
      if (
        t.isMemberExpression(callee) ||
        t.isOptionalMemberExpression(callee)
      ) {
        const method = semanticStaticPropertyKey(
          callee.property,
          callee.computed,
        );
        if (method === null || ARRAY_MUTATORS.has(method))
          for (const path of origins(callee.object))
            if (path[1] === null || path[1] === "f") retain(node, path);
      }
      const invocation = interop.intrinsicInvocation(node);
      if (
        invocation?.path.slice(0, -1).join(".") ===
          "intrinsic.Array.prototype" &&
        ARRAY_MUTATORS.has(invocation.path.at(-1) ?? "") &&
        invocation.receiver !== undefined
      )
        for (const path of origins(invocation.receiver))
          if (path[1] === null || path[1] === "f") retain(node, path);
      return invocation;
    },
    interop.staticString,
    interop.isFreshObject,
    retain,
  );
  if (allOwners) {
    let examined = 0;
    for (const owner of tables.keys()) {
      if (examined++ % 1024 === 0) yield;
      tables.set(owner, null);
    }
  }
}

function* createViteCacheOriginsSteps(
  tables: ReadonlyMap<string, CacheTable | null>,
  state: JavaScriptSemanticAnalysisState,
): Generator<void, (node: t.Node) => readonly CachePath[]> {
  const aliases = yield* indexViteAliasesSteps(state);
  const facts = new Map<AliasVertex, CacheOwnership>();
  const pending: { binding: AliasVertex; ownership: CacheOwnership }[] = [];
  // each binding has one owner or an ambiguous marker. each field can widen
  // only once, so retained facts and queued updates stay proportional to source.
  const retain = (binding: AliasVertex, incoming: CacheOwnership): void => {
    const previous = facts.get(binding);
    const ownership = joinOwnership(previous, incoming);
    if (ownership === previous) return;
    facts.set(binding, ownership);
    pending.push({ binding, ownership });
  };
  for (const owner of tables.keys())
    retain(owner, { owner, first: undefined, direct: true, shared: true });
  for (let cursor = 0; cursor < pending.length; cursor++) {
    if (cursor % 1024 === 0) yield;
    const fact = pending[cursor];
    if (fact === undefined) break;
    for (const alias of aliases.get(fact.binding) ?? []) {
      const source = selectOwnership(fact.ownership, alias.sourceFirst);
      if (source === undefined) continue;
      const copied =
        alias.copyKeepsCache === undefined
          ? source
          : {
              ...source,
              direct: false,
              shared:
                source.shared && source.first !== "f" && alias.copyKeepsCache,
            };
      const selected = selectOwnership(copied, alias.first);
      if (selected !== undefined) retain(alias.target, selected);
    }
  }
  const cached = new WeakMap<t.Node, readonly CachePath[]>();
  return (node) => {
    const previous = cached.get(node);
    if (previous !== undefined) return previous;
    let ownership: CacheOwnership | undefined;
    for (const [source, suffix] of viteAliasSources(node, state))
      if (facts.has(source)) {
        const selected = selectOwnership(facts.get(source), suffix);
        if (selected !== undefined)
          ownership = joinOwnership(ownership, selected);
      }
    const paths: readonly CachePath[] = ownership?.direct
      ? [
          ownership.first === undefined
            ? [ownership.owner]
            : [ownership.owner, ownership.first],
        ]
      : [];
    cached.set(node, paths);
    return paths;
  };
}

function* indexViteAliasesSteps(
  state: JavaScriptSemanticAnalysisState,
): Generator<void, ReadonlyMap<AliasVertex, readonly CacheAlias[]>> {
  const aliases = new Map<AliasVertex, CacheAlias[]>();
  const producers: t.Node[] = [];
  const spreadFacts = new WeakMap<t.Node, SpreadCacheFact>();
  const enqueued = new WeakSet<t.Node>();
  const normalize = (node: t.Node): void => {
    if (enqueued.has(node)) return;
    enqueued.add(node);
    producers.push(node);
  };
  const connect = (source: AliasVertex, alias: CacheAlias): void => {
    const targets = aliases.get(source) ?? [];
    targets.push(alias);
    aliases.set(source, targets);
  };
  let examined = 0;
  for (const binding of state.bindingsById.values()) {
    if (examined++ % 1024 === 0) yield;
    const initializers: readonly AliasInitializer[] = [
      ...binding.initializers,
      ...binding.referenceInitializers,
    ];
    for (const initializer of initializers) {
      if (initializer.copyKind === "array-rest") continue;
      const copied = initializer.copyKind === "object-rest";
      const projection =
        copied && initializer.copyProjectionOffset !== undefined
          ? initializer.projection.slice(0, initializer.copyProjectionOffset)
          : initializer.projection;
      const key = projection[0];
      normalize(initializer.node);
      connect(initializer.node, {
        target: binding.bindingId,
        first: copied
          ? undefined
          : key === undefined
            ? undefined
            : key === null
              ? null
              : String(key),
        ...(copied
          ? {
              sourceFirst:
                key === undefined
                  ? undefined
                  : key === null
                    ? null
                    : String(key),
              copyKeepsCache: semanticPropertyPathKeyMatches(
                {
                  excludedKeys: initializer.copyExcludedKeys ?? [],
                },
                "f",
              ),
            }
          : {}),
      });
    }
  }
  // shared initializer expressions are vertices, rather than duplicating all
  // branch sources for every destructured binding that reads that expression.
  for (let cursor = 0; cursor < producers.length; cursor++) {
    if (cursor % 1024 === 0) yield;
    const node = producers[cursor];
    if (node === undefined) break;
    for (const input of aliasProducerInputs(node, state, spreadFacts)) {
      if (typeof input.source !== "string") normalize(input.source);
      connect(input.source, {
        target: node,
        first: input.first,
        ...(input.copyKeepsCache === undefined
          ? {}
          : { copyKeepsCache: input.copyKeepsCache }),
      });
    }
  }
  return aliases;
}

const aliasProducerInputs = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  spreadFacts: WeakMap<t.Node, SpreadCacheFact>,
): readonly {
  source: AliasVertex;
  first: CacheKey;
  copyKeepsCache?: boolean;
}[] => {
  const { root, members } = electronMemberPath(node);
  const first = members[0];
  if (t.isIdentifier(root)) {
    const binding = resolveSemanticBindingState(state, root, root.name);
    return binding === undefined ? [] : [{ source: binding.bindingId, first }];
  }
  if (t.isObjectExpression(root)) {
    const inputs: {
      source: AliasVertex;
      first: CacheKey;
      copyKeepsCache: boolean;
    }[] = [];
    let overwritten = false;
    for (let index = root.properties.length - 1; index >= 0; index--) {
      const property = root.properties[index];
      if (property === undefined) continue;
      if (t.isSpreadElement(property)) {
        inputs.push({
          source: property.argument,
          first,
          copyKeepsCache: !overwritten,
        });
        if (spreadCacheFact(property.argument, spreadFacts) === "fresh")
          overwritten = true;
      } else {
        const key = semanticStaticPropertyKey(property.key, property.computed);
        if (
          key === "f" &&
          t.isObjectProperty(property) &&
          freshCacheReplacement(property.value)
        )
          overwritten = true;
      }
    }
    return inputs;
  }
  if (t.isConditionalExpression(root))
    return [
      { source: root.consequent, first },
      { source: root.alternate, first },
    ];
  if (t.isLogicalExpression(root))
    return [
      { source: root.left, first },
      { source: root.right, first },
    ];
  const source = t.isSequenceExpression(root)
    ? root.expressions.at(-1)
    : t.isAssignmentExpression(root, { operator: "=" })
      ? root.right
      : undefined;
  return source === undefined ? [] : [{ source, first }];
};

type SpreadCacheFact = "fresh" | "possible" | "absent";

const freshCacheReplacement = (node: t.Node): boolean =>
  t.isArrayExpression(node) ||
  t.isObjectExpression(node) ||
  t.isFunction(node) ||
  t.isStringLiteral(node) ||
  t.isNumericLiteral(node) ||
  t.isBooleanLiteral(node) ||
  t.isNullLiteral(node);

/** Read later literal spread keys once; unknown keys never prove lost ownership. */
const spreadCacheFact = (
  node: t.Node,
  facts: WeakMap<t.Node, SpreadCacheFact>,
): SpreadCacheFact => {
  const pending = [{ node, finish: false }];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || facts.has(current.node)) continue;
    if (!t.isObjectExpression(current.node)) {
      facts.set(
        current.node,
        freshCacheReplacement(current.node) ? "absent" : "possible",
      );
      continue;
    }
    if (!current.finish) {
      pending.push({ ...current, finish: true });
      for (const property of current.node.properties)
        if (t.isSpreadElement(property))
          pending.push({ node: property.argument, finish: false });
      continue;
    }
    let result: SpreadCacheFact = "absent";
    for (let index = current.node.properties.length - 1; index >= 0; index--) {
      const property = current.node.properties[index];
      if (property === undefined) continue;
      if (t.isSpreadElement(property)) {
        result = facts.get(property.argument) ?? "possible";
        if (result !== "absent") break;
      } else {
        const key = semanticStaticPropertyKey(property.key, property.computed);
        if (key === null) {
          result = "possible";
          break;
        }
        if (key === "f") {
          result =
            t.isObjectProperty(property) &&
            freshCacheReplacement(property.value)
              ? "fresh"
              : "possible";
          break;
        }
      }
    }
    facts.set(current.node, result);
  }
  return facts.get(node) ?? "possible";
};

const joinOwnership = (
  previous: CacheOwnership | undefined,
  incoming: CacheOwnership,
): CacheOwnership => {
  if (previous === undefined) return incoming;
  const joined = {
    owner: previous.owner === incoming.owner ? previous.owner : null,
    first: previous.first === incoming.first ? previous.first : null,
    direct: previous.direct || incoming.direct,
    shared: previous.shared || incoming.shared,
  };
  return joined.owner === previous.owner &&
    joined.first === previous.first &&
    joined.direct === previous.direct &&
    joined.shared === previous.shared
    ? previous
    : joined;
};

const selectOwnership = (
  source: CacheOwnership | undefined,
  first: CacheKey,
): CacheOwnership | undefined => {
  if (source === undefined || first === undefined) return source;
  if (!source.shared) return undefined;
  return {
    owner: source.owner,
    first: source.first === undefined ? first : source.first,
    direct: true,
    shared: true,
  };
};

/** only the first owned key distinguishes the admitted cache from other members. */
const viteAliasSources = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  first: CacheKey = undefined,
): ReadonlyMap<string, CacheKey> => {
  const sources = new Map<string, CacheKey>();
  const pending = [{ node, first }];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    const { root, members } = electronMemberPath(current.node);
    const key = members.length === 0 ? current.first : members[0];
    if (t.isIdentifier(root)) {
      const binding = resolveSemanticBindingState(state, root, root.name);
      if (binding === undefined) continue;
      const previous = sources.get(binding.bindingId);
      sources.set(
        binding.bindingId,
        sources.has(binding.bindingId) && previous !== key ? null : key,
      );
    } else if (t.isConditionalExpression(root))
      pending.push(
        { node: root.consequent, first: key },
        { node: root.alternate, first: key },
      );
    else if (t.isLogicalExpression(root))
      pending.push(
        { node: root.left, first: key },
        { node: root.right, first: key },
      );
    else if (t.isSequenceExpression(root)) {
      const last = root.expressions.at(-1);
      if (last !== undefined) pending.push({ node: last, first: key });
    } else if (t.isAssignmentExpression(root, { operator: "=" }))
      pending.push({ node: root.right, first: key });
  }
  return sources;
};
