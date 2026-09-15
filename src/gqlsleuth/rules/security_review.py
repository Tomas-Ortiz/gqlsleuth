"""Conservative GraphQL structural review using only retained project-owned metadata."""

from collections import deque
from uuid import UUID

from gqlsleuth.domain.analysis import OperationAnalysis, OperationKind
from gqlsleuth.domain.schema import ParsedSchema, SchemaField, SchemaNamedType, SchemaTypeKind
from gqlsleuth.domain.security_review import (
    GraphQLSecurityReviewCandidate,
    GraphQLSecurityReviewResult,
    SecurityCandidateType,
    SecurityReviewLimitation,
)
from gqlsleuth.graphql.collection_schema import (
    MAX_BOUNDING_INPUT_DEPTH,
    collection_paths,
    find_bounding_input,
)
from gqlsleuth.rules.operation_analysis import normalize_terms
from gqlsleuth.rules.schema_graph import (
    COMPOSITE_KINDS,
    MAX_GRAPH_RELATIONSHIPS,
    MAX_GRAPH_TYPES,
    TypeEdge,
    TypeGraph,
    build_type_graph,
    cycle_witnesses,
    format_path,
    reachable_paths,
)

FLEXIBLE_SCALARS = frozenset({"JSON", "JSONObject", "Any", "Map"})
MAX_COLLECTION_PATHS = 3
REQUIRED_INPUT_DEPTH_THRESHOLD = 4
_RANK = {kind: index for index, kind in enumerate(SecurityCandidateType)}


def order_candidates(
    candidates: tuple[GraphQLSecurityReviewCandidate, ...],
) -> tuple[GraphQLSecurityReviewCandidate, ...]:
    """One candidate per type/endpoint/subject, ordered by enum rank then exact identifiers."""
    unique = {(item.candidate_type, item.endpoint, item.subject): item for item in candidates}
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (_RANK[item.candidate_type], item.endpoint, item.subject),
        )
    )


def review_schema(
    endpoint: str,
    schema: ParsedSchema,
    operations: tuple[OperationAnalysis, ...] = (),
    *,
    source_evidence_ids: tuple[UUID, ...] = (),
) -> GraphQLSecurityReviewResult:
    """Never generate documents, classify runtime outcomes, or invoke infrastructure."""
    types = {item.name: item for item in schema.types}
    related = {(item.kind, item.name): item for item in operations if item.endpoint == endpoint}
    candidates: list[GraphQLSecurityReviewCandidate] = []
    limitations = []
    input_graph = build_type_graph(schema.types, inputs=True)
    output_graph = build_type_graph(schema.types, inputs=False)
    for label, graph in (("Input", input_graph), ("Output", output_graph)):
        if graph.truncated:
            limitations.append(
                SecurityReviewLimitation(
                    endpoint,
                    f"{label} graph review was partial: internal limits of {MAX_GRAPH_TYPES} types "
                    f"and {MAX_GRAPH_RELATIONSHIPS} inspected relationships were reached. "
                    "Unexamined structure supports no absence conclusion.",
                )
            )

    def add(
        kind: SecurityCandidateType,
        subject: str,
        reason: str,
        facts: tuple[str, ...],
        guidance: str,
        operation: OperationAnalysis | None = None,
    ) -> None:
        candidates.append(
            GraphQLSecurityReviewCandidate(
                kind, endpoint, subject, reason, facts, guidance, operation, source_evidence_ids
            )
        )

    input_cycles = cycle_witnesses(input_graph, require_list=False)
    upload_used = False
    for kind, root_name in (
        (OperationKind.QUERY, schema.query_root),
        (OperationKind.MUTATION, schema.mutation_root),
    ):
        root = types.get(root_name) if root_name else None
        if root is None:
            continue
        for field in sorted(root.fields, key=lambda field: field.name):
            subject = f"{kind.value} {field.name}"
            operation = related.get((kind, field.name))
            output = types.get(field.type.named_type)
            if kind is OperationKind.QUERY and output and output.kind in COMPOSITE_KINDS:
                identifiers = tuple(
                    f"Argument {arg.name}: {arg.type.render()}"
                    for arg in sorted(field.arguments, key=lambda arg: arg.name)
                    if arg.type.named_type == "ID"
                    and normalize_terms(arg.name)
                    and normalize_terms(arg.name)[-1] in {"id", "ids"}
                )
                if identifiers:
                    add(
                        SecurityCandidateType.OBJECT_LOOKUP_REVIEW,
                        subject,
                        "Top-level object lookup accepts an identifier "
                        "and returns application objects."
                        + (
                            " A global/node lookup pattern is exposed."
                            if field.name in {"node", "nodes"}
                            else ""
                        ),
                        (*identifiers, f"Return type: {field.type.render()}"),
                        "Where these objects are access-controlled, manually verify object-level "
                        "authorization across appropriate identities/tenants.",
                        operation,
                    )
                collection_facts = _collection_facts(field, output, types)
                if collection_facts and find_bounding_input(field, types) is None:
                    add(
                        SecurityCandidateType.LIST_BOUNDING_REVIEW,
                        subject,
                        (
                            "Query returns a list of application objects"
                            if field.type.is_list
                            else "Query exposes a collection through a one-level wrapper"
                        )
                        + " and no obvious result-size bounding input was observed in the schema.",
                        (
                            *collection_facts,
                            "Obvious bounding input: none observed "
                            f"(root arguments and up to {MAX_BOUNDING_INPUT_DEPTH} "
                            "input-object levels).",
                        ),
                        "Review server-side result limits, pagination defaults and "
                        "query-complexity controls. Runtime controls may exist outside the schema; "
                        "this is not proof of unlimited results. A bounding input's presence "
                        "does not prove runtime enforcement.",
                        operation,
                    )

            scalar_paths, complex_facts = _input_facts(field, types, input_graph, input_cycles)
            for scalar, path in sorted(scalar_paths.items()):
                if scalar == "Upload" and kind is OperationKind.MUTATION:
                    upload_used = True
                    add(
                        SecurityCandidateType.FILE_UPLOAD_SURFACE,
                        subject,
                        "Mutation input reaches the Upload custom scalar.",
                        (f"Input path: {path}", "Custom scalar: Upload"),
                        "Manually review content/type validation, size limits, authorization, "
                        "storage behavior and filename/content handling.",
                        operation,
                    )
            flexible = tuple(
                (name, path)
                for name, path in sorted(scalar_paths.items())
                if name in FLEXIBLE_SCALARS
            )
            if flexible:
                add(
                    SecurityCandidateType.FLEXIBLE_SCALAR_INPUT_REVIEW,
                    subject,
                    "Root operation accepts a broad/unstructured custom scalar.",
                    tuple(f"{name} input path: {path}" for name, path in flexible),
                    "Manually review allowed structure, field-level validation, unexpected "
                    "properties and authorization of configurable fields.",
                    operation,
                )
            if complex_facts:
                add(
                    SecurityCandidateType.COMPLEX_INPUT_REVIEW,
                    subject,
                    "Root input has a recursive relationship or a required input-object chain "
                    f"deeper than {REQUIRED_INPUT_DEPTH_THRESHOLD} objects.",
                    complex_facts,
                    "Manually review input validation, nesting limits "
                    "and recursive input handling. "
                    "This schema structure alone does not establish runtime impact.",
                    operation,
                )
            if field.is_deprecated and operation and operation.interest_score > 0:
                add(
                    SecurityCandidateType.DEPRECATED_SECURITY_RELEVANT_OPERATION,
                    subject,
                    "A deprecated root operation with existing Phase 7 review interest "
                    "remains exposed.",
                    ("Deprecation reason: " + (field.deprecation_reason or "Not supplied"),),
                    "Manually compare legacy behavior and intended access controls with its "
                    "replacement, where one exists.",
                    operation,
                )

    upload = types.get("Upload")
    if upload and upload.kind is SchemaTypeKind.SCALAR and not upload_used:
        add(
            SecurityCandidateType.FILE_UPLOAD_SURFACE,
            "scalar Upload",
            "The schema declares the Upload custom scalar; runtime upload support is unverified.",
            ("Custom scalar: Upload", "No reachable Mutation Upload input was observed."),
            "Manually establish whether upload functionality is exposed and review its "
            "validation, size limits, authorization and storage behavior.",
        )

    federation = _federation_facts(schema, types)
    if federation:
        add(
            SecurityCandidateType.FEDERATION_SURFACE,
            "endpoint",
            "Coherent federation-specific Query and type structures were observed.",
            federation,
            "Manually review subgraph exposure, entity-resolution authorization and trust "
            "boundaries between federated components. No server vendor is inferred.",
        )
    subscription = types.get(schema.subscription_root) if schema.subscription_root else None
    if subscription and subscription.fields:
        add(
            SecurityCandidateType.SUBSCRIPTION_SURFACE,
            subscription.name,
            f"Subscription root exposes {len(subscription.fields)} operation(s).",
            (
                f"Root: {subscription.name}",
                "Operations: " + ", ".join(sorted(field.name for field in subscription.fields)),
            ),
            "Manually review connection authentication, per-subscription authorization, "
            "event filtering, tenant/user isolation and session lifecycle.",
        )
    reachable = reachable_paths(output_graph, (schema.query_root,))
    for cycle in cycle_witnesses(output_graph, require_list=True):
        if cycle[0].source in reachable:
            add(
                SecurityCandidateType.RECURSIVE_GRAPH_REVIEW,
                cycle[0].label,
                "A Query-reachable output cycle contains a list-valued composite relationship.",
                ("Cycle: " + format_path(cycle),),
                "Manually review query-depth and complexity controls; schema recursion alone "
                "does not establish runtime impact.",
            )
    return GraphQLSecurityReviewResult(
        order_candidates(tuple(candidates)), tuple(limitations), (endpoint,)
    )


def _collection_facts(
    field: SchemaField,
    output: SchemaNamedType,
    types: dict[str, SchemaNamedType],
) -> tuple[str, ...]:
    """Direct composite lists or one high-signal wrapper level; never follow output edges."""
    if field.type.is_list:
        return (f"Return type: {field.type.render()}", f"Element type: {output.name}")
    collections = collection_paths(field, types)
    facts = tuple(
        fact
        for path, element in collections[:MAX_COLLECTION_PATHS]
        for fact in (f"Collection path: {path}", f"Element type: {element}")
    )
    if len(collections) > MAX_COLLECTION_PATHS:
        facts += (
            f"Additional qualifying collection fields: {len(collections) - MAX_COLLECTION_PATHS}.",
        )
    return facts


def _federation_facts(schema: ParsedSchema, types: dict[str, SchemaNamedType]) -> tuple[str, ...]:
    root = types.get(schema.query_root)
    fields = {field.name: field for field in root.fields} if root else {}
    service = fields.get("_service")
    service_type = types.get("_Service")
    entities = fields.get("_entities")
    any_type, entity_type = types.get("_Any"), types.get("_Entity")
    facts: list[str] = []
    if (
        service
        and service.type.named_type == "_Service"
        and service_type
        and service_type.kind is SchemaTypeKind.OBJECT
        and any(
            field.name == "sdl" and field.type.named_type == "String"
            for field in service_type.fields
        )
    ):
        facts.extend(("Query._service returns _Service", "_Service.sdl: String"))
    if (
        entities
        and entities.type.is_list
        and entities.type.named_type == "_Entity"
        and entity_type
        and entity_type.kind is SchemaTypeKind.UNION
        and any_type
        and any_type.kind is SchemaTypeKind.SCALAR
        and any(
            arg.name == "representations" and arg.type.is_list and arg.type.named_type == "_Any"
            for arg in entities.arguments
        )
    ):
        facts.extend(
            (
                "Query._entities returns [_Entity]",
                "_Entity union",
                "_Any scalar",
                "_entities(representations: [_Any])",
            )
        )
    return tuple(facts)


def _input_facts(
    field: SchemaField,
    types: dict[str, SchemaNamedType],
    graph: TypeGraph,
    cycles: tuple[tuple[TypeEdge, ...], ...],
) -> tuple[dict[str, str], tuple[str, ...]]:
    scalars: dict[str, str] = {}
    complex_facts: list[str] = []
    for arg in sorted(field.arguments, key=lambda arg: arg.name):
        paths = reachable_paths(graph, (arg.type.named_type,))
        for name, path in paths.items():
            if types[name].kind is SchemaTypeKind.SCALAR:
                scalars.setdefault(
                    name,
                    f"{field.name}({arg.name}: {arg.type.render()})"
                    + (" -> " + format_path(path) if path else ""),
                )
        for cycle in cycles:
            if cycle[0].source in paths:
                fact = "Recursive input: " + format_path(cycle)
                if fact not in complex_facts:
                    complex_facts.append(fact)
        if arg.type.outer_non_null and arg.default_value is None:
            deep = _required_path(graph, arg.type.named_type, types)
            if deep:
                complex_facts.append(f"Required input from {arg.name}: " + format_path(deep))
    return scalars, tuple(complex_facts)


def _required_path(
    graph: TypeGraph,
    start: str,
    types: dict[str, SchemaNamedType],
) -> tuple[TypeEdge, ...]:
    """Depth-capped states avoid exponential traversal and Python recursion limits."""
    if start not in graph.edges or types[start].kind is not SchemaTypeKind.INPUT_OBJECT:
        return ()
    queue: deque[tuple[str, tuple[TypeEdge, ...]]] = deque([(start, ())])
    seen = {(start, 1)}
    while queue:
        name, path = queue.popleft()
        for edge in graph.edges[name]:
            if not edge.required or types[edge.target].kind is not SchemaTypeKind.INPUT_OBJECT:
                continue
            next_path = (*path, edge)
            if len(next_path) >= REQUIRED_INPUT_DEPTH_THRESHOLD:
                return next_path
            state = (edge.target, len(next_path) + 1)
            if state not in seen:
                seen.add(state)
                queue.append((edge.target, next_path))
    return ()
