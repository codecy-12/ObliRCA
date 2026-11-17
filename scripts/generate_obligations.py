"""Generate the ten security-obligation entries.

The entries are intentionally abstract: they contain roles, object-relation
graphs, conditions, and a query manual, but no program names, source locations,
CVE identifiers, or payloads.  The graph counts mirror the category coverage in
the paper's appendix (7/4/8/12/9/10/6/7/8/7, 78 graphs total).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "obligations"


def role(name: str, description: str, kind: str = "object") -> dict[str, str]:
    return {"name": name, "description": description, "kind": kind}


def graph_variant(index: int, roles: dict[str, dict[str, str]], category: str) -> dict[str, Any]:
    """Return one of twelve abstract object organizations."""
    r = list(roles)
    src, val, tgt, pol, aux = (r + r)[:5]
    n = lambda i, role_name, kind="object", desc="": {
        "id": f"n{i}",
        "role": role_name,
        "kind": kind,
        "description": desc,
    }
    variants = [
        (
            "direct value-to-target organization",
            [n(1, src), n(2, val, "value"), n(3, tgt)],
            [(1, 2, "provides"), (2, 3, "constrains")],
        ),
        (
            "wrapper-mediated organization",
            [n(1, src), n(2, aux, "function"), n(3, tgt)],
            [(1, 2, "enters"), (2, 3, "invokes")],
        ),
        (
            "container-mediated organization",
            [n(1, src), n(2, aux), n(3, tgt)],
            [(1, 2, "populates"), (2, 3, "reaches")],
        ),
        (
            "alias/reference organization",
            [n(1, src), n(2, aux), n(3, tgt)],
            [(1, 2, "aliases"), (2, 3, "is_used_by")],
        ),
        (
            "split source and value organization",
            [n(1, src), n(2, val, "value"), n(3, tgt), n(4, pol)],
            [(1, 2, "supplies"), (2, 3, "bounds"), (4, 3, "governs")],
        ),
        (
            "policy-governed organization",
            [n(1, src), n(2, tgt), n(3, pol), n(4, val, "value")],
            [(1, 2, "requests"), (3, 2, "governs"), (4, 2, "parameterizes")],
        ),
        (
            "boundary-crossing organization",
            [n(1, src), n(2, aux, "boundary"), n(3, tgt)],
            [(1, 2, "crosses"), (2, 3, "delivers")],
        ),
        (
            "state-mediated organization",
            [n(1, src), n(2, aux, "state"), n(3, tgt)],
            [(1, 2, "updates"), (2, 3, "enables")],
        ),
        (
            "multi-source organization",
            [n(1, src), n(2, aux), n(3, tgt), n(4, pol)],
            [(1, 3, "influences"), (2, 3, "influences"), (4, 3, "governs")],
        ),
        (
            "transformation organization",
            [n(1, src), n(2, aux, "function"), n(3, tgt), n(4, val, "value")],
            [(1, 2, "is_transformed"), (2, 3, "is_consumed"), (4, 3, "parameterizes")],
        ),
        (
            "range/offset organization",
            [n(1, src), n(2, val, "value"), n(3, tgt), n(4, aux, "value")],
            [(1, 2, "defines"), (4, 3, "offsets"), (2, 3, "limits")],
        ),
        (
            "ownership organization",
            [n(1, src), n(2, aux, "owner"), n(3, tgt), n(4, pol)],
            [(2, 3, "owns"), (1, 3, "accesses"), (4, 3, "governs")],
        ),
    ]
    description, nodes, edges = variants[index % len(variants)]
    return {
        "id": f"G{index + 1}",
        "description": description,
        "nodes": nodes,
        "edges": [
            {"src": f"n{a}", "dst": f"n{b}", "relation": rel, "description": ""}
            for a, b, rel in edges
        ],
    }


CATEGORIES: list[dict[str, Any]] = [
    {
        "id": "OBL-PATH-001",
        "category": "Path Constraints",
        "category_id": 1,
        "graphs": 7,
        "cases": 128,
        "summary": "A path derived from an untrusted source must resolve within the intended root and denote the intended object.",
        "roles": {
            "source": role("untrusted_path", "untrusted path or path component"),
            "value": role("path_representation", "normalized or encoded path representation", "value"),
            "target": role("filesystem_target", "file or directory reached by the path"),
            "policy": role("root_boundary", "root, mount, or namespace boundary"),
            "aux": role("resolver", "resolution or canonicalization routine"),
        },
        "conditions": {
            "pre": ["a path or path component from an untrusted source is about to be resolved or used"],
            "must": ["the resolved path remains within the intended root and denotes the intended object"],
            "stage": ["before the target is opened, read, written, or executed"],
            "scope": ["until the operation completes; recheck after symlink, mount, or root changes"],
        },
        "queries": [
            ("Where is the path canonicalized or normalized?", "trace definitions, joins, and resolver calls before the target", "a canonical form computed under the intended root answers the question", "continue to the target if the root is established"),
            ("Which root or boundary governs the target?", "trace the root, mount, and namespace values into the operation", "a root check that dominates the target answers the question", "record a gap if the target can leave the root"),
            ("Can a symlink or parent component change the resolution?", "inspect link following, parent traversal, and time-of-check windows", "a post-resolution containment check answers the question", "continue if containment is checked after resolution"),
            ("Is an encoded or alternate representation decoded later?", "follow decoders, joins, and alternate separators", "a second normalization after decoding is required", "recheck containment after the last decode"),
            ("Does the check survive a rename, mount, or namespace change?", "inspect updates to the root and object identity", "a stable object identity or recheck answers the question", "record a gap if the check is stale"),
        ],
    },
    {
        "id": "OBL-AUTH-001",
        "category": "Authorization Checks",
        "category_id": 2,
        "graphs": 4,
        "cases": 181,
        "summary": "The authenticated subject and its granted scope must cover the requested action on the actual target.",
        "roles": {
            "source": role("subject", "authenticated subject or client identity"),
            "value": role("credential", "authentication result or granted scope", "value"),
            "target": role("action", "requested operation and target object"),
            "policy": role("policy_context", "policy, host, or tenant context"),
            "aux": role("policy_engine", "authorization or policy evaluation routine"),
        },
        "conditions": {
            "pre": ["a request reaches a protected operation"],
            "must": ["the authenticated subject and its granted scope cover the requested action on the actual target"],
            "stage": ["before the protected operation is performed"],
            "scope": ["until the operation completes; recheck after identity, host, tenant, or policy changes"],
        },
        "queries": [
            ("Where does the authentication result originate?", "trace the credential verification and the value it produces", "a result that is bound to the actual subject and context answers the question", "continue if the result is available"),
            ("Is the subject bound to the requested action and target?", "trace subject, action, and target into the policy decision", "a decision that uses all three answers the question", "record a gap if one is substituted or omitted"),
            ("Does the policy apply to the actual host or tenant?", "compare the policy context with the runtime context", "a consistency check before the decision answers the question", "continue if the contexts are checked"),
            ("Can the policy version change between check and use?", "inspect reloads, caches, and deferred decisions", "a stable snapshot or recheck answers the question", "record a gap if the decision is stale"),
            ("Is an upstream check sufficient for this target?", "trace callers and wrappers into the protected operation", "a dominating upstream check with the same context answers the question", "reassess sufficiency if only a partial check exists"),
        ],
    },
    {
        "id": "OBL-RES-001",
        "category": "Resource Bounds",
        "category_id": 3,
        "graphs": 8,
        "cases": 139,
        "summary": "The requested amount plus current consumption must remain within the configured bound for a shared resource.",
        "roles": {
            "source": role("requester", "request or principal that consumes the resource"),
            "value": role("amount", "requested amount, rate, or count", "value"),
            "target": role("resource", "bounded resource or admission point"),
            "policy": role("quota_policy", "configured bound or quota"),
            "aux": role("accounting", "accounting or admission routine"),
        },
        "conditions": {
            "pre": ["a request can consume a shared or bounded resource"],
            "must": ["the requested amount plus current consumption stays within the configured bound"],
            "stage": ["before allocation, enqueue, or admission"],
            "scope": ["until the resource is released or the request completes"],
        },
        "queries": [
            ("Where is the bound configured?", "trace the quota or limit from configuration to the admission point", "a bound that is read by the admission check answers the question", "continue if the bound is established"),
            ("Is current consumption accounted for atomically?", "inspect counters, reservations, and concurrent updates", "an atomic reservation answers the question", "record a gap if the check races with consumption"),
            ("Can the request exceed the bound after a retry or split?", "trace retries, batches, and decomposition", "accounting that covers all parts answers the question", "continue if the whole request is accounted"),
            ("Is the resource released on every error path?", "inspect rollback, cleanup, and exception paths", "a release that matches every acquisition answers the question", "record a gap if an error path leaks the reservation"),
            ("Does the bound reset or expire correctly?", "inspect timers, windows, and reset logic", "a reset that preserves the invariant answers the question", "continue if the window is well defined"),
        ],
    },
    {
        "id": "OBL-PROTO-001",
        "category": "Protocol State Constraints",
        "category_id": 4,
        "graphs": 12,
        "cases": 91,
        "summary": "A message must be valid for the current protocol state and the negotiated version before it is dispatched.",
        "roles": {
            "source": role("peer", "remote peer or session endpoint"),
            "value": role("message", "protocol message or frame", "value"),
            "target": role("state", "current protocol state or session state"),
            "policy": role("expected_state", "expected state, version, or transition rule"),
            "aux": role("dispatcher", "parser or state-machine dispatcher"),
        },
        "conditions": {
            "pre": ["a message is accepted on an existing or new session"],
            "must": ["the message is valid for the current protocol state and the negotiated version"],
            "stage": ["before the message is dispatched or a state transition is committed"],
            "scope": ["until the transition is committed; recheck after retry, resumption, or renegotiation"],
        },
        "queries": [
            ("Which state transition does this message require?", "trace the state variable and the transition table", "a transition guard that covers the message answers the question", "continue if the transition is valid"),
            ("Is the negotiated version part of the check?", "trace version negotiation and feature flags", "a check that uses the negotiated version answers the question", "record a gap if a version-dependent feature is unchecked"),
            ("Can a resumed or retried session skip the transition?", "inspect resumption, retry, and replay paths", "a resumption path that revalidates state answers the question", "continue if the state is reestablished"),
            ("Can messages arrive out of order?", "inspect queues, demultiplexing, and sequence numbers", "an ordering rule that is enforced answers the question", "record a gap if reordering is accepted"),
            ("Does the state update commit before the side effect?", "inspect the order of state write and dispatch", "a commit-before-dispatch order answers the question", "continue if the side effect is after the commit"),
        ],
    },
    {
        "id": "OBL-MEM-001",
        "category": "Memory Bounds",
        "category_id": 5,
        "graphs": 9,
        "cases": 332,
        "summary": "The accessed range must lie within the allocated or valid range of the same object before a memory operation.",
        "roles": {
            "source": role("external_data", "externally influenced data or index"),
            "value": role("length", "length, offset, count, or index", "value"),
            "target": role("buffer", "buffer, allocation, or valid range"),
            "policy": role("valid_range", "allocation size or valid range", "value"),
            "aux": role("operation", "read, write, copy, or index operation"),
        },
        "conditions": {
            "pre": ["a read, write, copy, or index operation uses an externally influenced length or offset"],
            "must": ["the accessed range lies within the allocated or valid range of the same object"],
            "stage": ["before the memory operation"],
            "scope": ["until the operation completes; recheck after reallocation, length update, or aliasing"],
        },
        "queries": [
            ("Where does the length or offset come from?", "trace the value from its source into the operation", "a value derived from a checked range answers the question", "continue if the origin is established"),
            ("What is the valid range of the target?", "trace allocation, capacity, and updates", "a capacity that dominates the operation answers the question", "record a gap if the capacity is stale or unknown"),
            ("Can the length arithmetic overflow or wrap?", "inspect additions, multiplications, and casts before the check", "an overflow-safe check answers the question", "continue if the arithmetic is bounded"),
            ("Does the check use the same object and representation?", "compare the checked object with the operated object", "a check on the same object and representation answers the question", "record a gap if the check is on a copy or alias"),
            ("Can the range change after the check?", "inspect reallocation, concurrent updates, and callbacks", "a stable range or recheck answers the question", "continue if the range is protected"),
        ],
    },
    {
        "id": "OBL-INPUT-001",
        "category": "Input Sanitization",
        "category_id": 6,
        "graphs": 10,
        "cases": 237,
        "summary": "Untrusted input must be normalized and constrained to the expected grammar before it is parsed or interpreted.",
        "roles": {
            "source": role("untrusted_input", "raw input from an external source"),
            "value": role("encoding", "encoding, escaping, or representation", "value"),
            "target": role("parser", "parser, interpreter, or command constructor"),
            "policy": role("grammar", "expected grammar, type, or policy"),
            "aux": role("sanitizer", "normalization or validation routine"),
        },
        "conditions": {
            "pre": ["untrusted input is parsed, decoded, or passed to an interpreter"],
            "must": ["the input is normalized and constrained to the expected grammar before use"],
            "stage": ["before parsing, decoding, or command construction"],
            "scope": ["until the value is consumed; recheck after a second decoding or concatenation"],
        },
        "queries": [
            ("Where is the input decoded or normalized?", "trace decoders, encoders, and transformations", "a normalization that matches the expected grammar answers the question", "continue if the representation is stable"),
            ("Does the parser accept metacharacters or alternate syntax?", "inspect the parser grammar and separators", "a parser that rejects or escapes them answers the question", "record a gap if the grammar is permissive"),
            ("Can a second decode change the value after validation?", "inspect repeated decoding and concatenation", "a validation after the last decode answers the question", "continue if the value is final"),
            ("Is the input checked for type and length?", "trace the type and length into the consumer", "a check that covers the consumer's expectation answers the question", "record a gap if the consumer assumes an unchecked type"),
            ("Does the sanitizer preserve the original meaning?", "compare the sanitized and consumed values", "a sanitizer that preserves the intended value answers the question", "continue if the value is not corrupted"),
        ],
    },
    {
        "id": "OBL-DEFAULT-001",
        "category": "Secure Defaults",
        "category_id": 7,
        "graphs": 6,
        "cases": 47,
        "summary": "The effective configuration must be deny-by-default and consistent with the deployment policy when an option is absent or inherited.",
        "roles": {
            "source": role("configuration", "configuration source or inheritance chain"),
            "value": role("option", "security-relevant option or flag", "value"),
            "target": role("effective_policy", "effective policy or protected operation"),
            "policy": role("deployment_policy", "deployment security policy"),
            "aux": role("merge", "merge or precedence routine"),
        },
        "conditions": {
            "pre": ["a security-relevant option is absent, inherited, or left at its default"],
            "must": ["the effective configuration is deny-by-default and consistent with the deployment policy"],
            "stage": ["before the option is applied to the protected operation"],
            "scope": ["until the configuration is reloaded; recheck after inheritance, merge, or override"],
        },
        "queries": [
            ("What is the default value and who applies it?", "trace the option definition and default assignment", "a deny-by-default value answers the question", "continue if the default is secure"),
            ("Which precedence order applies?", "inspect merge and override rules", "an order that preserves the secure value answers the question", "record a gap if an override silently weakens it"),
            ("Can inheritance introduce an unsafe value?", "trace parent, tenant, or profile inheritance", "an inheritance check that rejects unsafe values answers the question", "continue if inherited values are validated"),
            ("Is the option applied to the actual deployment context?", "compare the option with the runtime context", "a context-aware check answers the question", "record a gap if the option is applied blindly"),
            ("Does a reload restore the secure value?", "inspect reload and rollback paths", "a reload that revalidates the policy answers the question", "continue if the reload is safe"),
        ],
    },
    {
        "id": "OBL-CONC-001",
        "category": "Concurrency Ordering",
        "category_id": 8,
        "graphs": 7,
        "cases": 55,
        "summary": "A read-modify-write sequence on shared state must be atomic with respect to all conflicting accesses.",
        "roles": {
            "source": role("actor", "thread, process, or request actor"),
            "value": role("shared_state", "shared variable, object, or queue", "object"),
            "target": role("operation", "read-modify-write or check-then-act sequence"),
            "policy": role("lock", "lock, atomic primitive, or ordering rule"),
            "aux": role("observer", "competing accessor or observer"),
        },
        "conditions": {
            "pre": ["two or more actors can access shared state concurrently"],
            "must": ["the read-modify-write sequence is atomic with respect to all conflicting accesses"],
            "stage": ["before the first access in the critical sequence"],
            "scope": ["until the sequence commits; recheck after lock release, retry, or reentrancy"],
        },
        "queries": [
            ("Which accesses conflict with the sequence?", "enumerate readers, writers, and callbacks on the shared state", "a lock or atomic primitive that covers all conflicting accesses answers the question", "continue if the critical section is complete"),
            ("Is the check and the use in the same critical section?", "trace the check, the use, and the lock boundaries", "a check that remains valid until the use answers the question", "record a gap if the check can be invalidated"),
            ("Can a retry or callback reenter the sequence?", "inspect reentrancy and deferred work", "a reentrancy-safe primitive answers the question", "continue if reentrancy is excluded"),
            ("Is the ordering visible to all actors?", "inspect memory barriers and publication", "a barrier or atomic publication answers the question", "record a gap if publication is unordered"),
            ("Does an error path release the lock correctly?", "inspect unwind, timeout, and cancellation", "a release that matches every acquisition answers the question", "continue if the error path is safe"),
        ],
    },
    {
        "id": "OBL-RLIFE-001",
        "category": "Resource Lifecycles",
        "category_id": 9,
        "graphs": 8,
        "cases": 41,
        "summary": "Every acquired resource must be released exactly once by a valid owner across all paths.",
        "roles": {
            "source": role("resource", "file, connection, handle, or memory resource"),
            "value": role("handle", "handle or reference used to access the resource", "value"),
            "target": role("release", "release or destruction operation"),
            "policy": role("owner", "owner or lifetime rule"),
            "aux": role("operation", "acquisition, transfer, or use operation"),
        },
        "conditions": {
            "pre": ["a resource is acquired, transferred, or released"],
            "must": ["every acquired resource is released exactly once by a valid owner"],
            "stage": ["before acquisition and at every transfer or error path"],
            "scope": ["until the resource is destroyed; recheck after fork, duplication, or exception"],
        },
        "queries": [
            ("Where is the resource acquired?", "trace acquisition and the resulting handle", "a handle with a clear owner answers the question", "continue if ownership is established"),
            ("Who owns the resource after each transfer?", "trace transfers, duplication, and callbacks", "a single valid owner at each point answers the question", "record a gap if ownership is ambiguous"),
            ("Is the resource released on every error path?", "inspect unwind, timeout, and cancellation", "a release that matches every acquisition answers the question", "continue if all paths release"),
            ("Can the resource be released twice?", "inspect aliases, callbacks, and idempotency", "a release that is exactly once answers the question", "record a gap if double release is possible"),
            ("Does the release order respect dependencies?", "inspect nested resources and destruction order", "a dependency-safe order answers the question", "continue if the order is safe"),
        ],
    },
    {
        "id": "OBL-OLIFE-001",
        "category": "Object Lifecycles",
        "category_id": 10,
        "graphs": 7,
        "cases": 72,
        "summary": "An object must remain valid for every use and be destroyed only when no references remain.",
        "roles": {
            "source": role("object", "object whose lifetime is managed"),
            "value": role("reference", "reference, pointer, or handle", "value"),
            "target": role("operation", "use or destruction operation"),
            "policy": role("state", "initialized, alive, or destroyed state", "value"),
            "aux": role("owner", "owner or reference-count manager"),
        },
        "conditions": {
            "pre": ["an object is created, referenced, or destroyed"],
            "must": ["the object remains valid for every use and is destroyed only when no references remain"],
            "stage": ["before each use and before destruction"],
            "scope": ["until the last reference is released; recheck after reentrancy, callback, or error"],
        },
        "queries": [
            ("Where is the object initialized?", "trace allocation and initialization", "a fully initialized object before publication answers the question", "continue if initialization is complete"),
            ("Who holds references and for how long?", "trace references, aliases, and ownership", "a reference count or ownership rule that covers every use answers the question", "record a gap if a reference can outlive the object"),
            ("Can a callback or reentrant path use the object after destruction?", "inspect callbacks, deferred work, and error paths", "a lifetime guard that covers the callback answers the question", "continue if the callback is safe"),
            ("Is destruction ordered after the last use?", "inspect destruction and publication order", "a last-use-before-destroy order answers the question", "record a gap if destruction can precede a use"),
            ("Is a failed initialization cleaned up?", "inspect partial initialization and rollback", "a cleanup that matches every partial state answers the question", "continue if rollback is complete"),
        ],
    },
]


def build_entry(spec: dict[str, Any]) -> dict[str, Any]:
    queries = [
        {
            "id": f"Q{i + 1}",
            "what": what,
            "where": where,
            "interpret": interpret,
            "next": next_action,
        }
        for i, (what, where, interpret, next_action) in enumerate(spec["queries"])
    ]
    graphs = [
        graph_variant(i, spec["roles"], spec["category"])
        for i in range(spec["graphs"])
    ]
    return {
        "id": spec["id"],
        "category": spec["category"],
        "category_id": spec["category_id"],
        "version": "1.0.0",
        "summary": spec["summary"],
        "roles": spec["roles"],
        "graphs": graphs,
        "conditions": spec["conditions"],
        "query_manual": queries,
        "provenance": {
            "category_id": spec["category_id"],
            "graph_count": spec["graphs"],
            "source_cases": spec["cases"],
            "accepted_round": 1,
            "revision_count": 0,
            "created_from": "offline-flywheel",
            "notes": "abstract entry; no historical identifiers",
        },
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    total_graphs = 0
    for spec in CATEGORIES:
        entry = build_entry(spec)
        path = OUT / f"{spec['category_id']:02d}_{spec['category'].lower().replace(' ', '_')}.yaml"
        with path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(entry, fh, sort_keys=False, allow_unicode=True)
        total_graphs += spec["graphs"]
        print(f"{path.name}: {spec['graphs']} graphs, {spec['cases']} cases")
    print(f"total: {len(CATEGORIES)} entries, {total_graphs} graphs")


if __name__ == "__main__":
    main()
