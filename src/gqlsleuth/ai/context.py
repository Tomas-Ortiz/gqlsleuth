"""Construct AI input from an explicit allowlist, without serializing scan objects."""

import json

from gqlsleuth.ai.identifiers import identifier as _identifier
from gqlsleuth.ai.models import (
    MAX_AI_OPERATIONS,
    MAX_CONTEXT_BYTES,
    AIContext,
    AIContextMetadata,
    AIOperation,
    AISchemaSummary,
)
from gqlsleuth.ai.security_context import ordered_security_context
from gqlsleuth.application.active_execution import ActiveExecutionScanResult
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.analysis import PRIORITY_RANK, OperationKind
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.models import EvidenceType


def serialize_context(context: AIContext) -> str:
    """The single serialization path used for byte limits and the actual Ollama request."""
    value = context.model_dump(mode="json")
    value["security_facts"] = [
        fact.model_dump(mode="json", exclude_none=True) for fact in context.security_facts
    ]
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def build_ai_context(result: SafeExecutionScanResult | ActiveExecutionScanResult) -> AIContext:
    """Read named fields only. No URLs, documents, variables, descriptions, or error text."""
    if not isinstance(result, (SafeExecutionScanResult, ActiveExecutionScanResult)):
        raise ValueError("AI interpretation supports single-context completed scans only.")
    active = result if isinstance(result, ActiveExecutionScanResult) else None
    safe = active.safe_execution if active else result
    assert isinstance(safe, SafeExecutionScanResult)
    security_facts, coverage = ordered_security_context(safe, active)
    security_facts_total = len(security_facts)
    analysis = safe.query_generation.operation_analysis
    schema_scan = analysis.schema_scan
    introspection = schema_scan.introspection
    endpoints = {item.endpoint: f"endpoint_{i}" for i, item in enumerate(analysis.endpoints, 1)}
    operations = [operation for item in analysis.endpoints for operation in item.operations]
    # Stable sort preserves retained Phase 7 order within equal priorities/scores.
    operations.sort(key=lambda item: (PRIORITY_RANK[item.priority], -item.interest_score))
    queries = {(item.endpoint, item.operation_name): item for item in safe.query_generation.queries}
    executions = {(item.endpoint, item.operation_name): item for item in safe.executions}
    candidates = (
        {
            (item.generated_mutation.endpoint, item.generated_mutation.operation_name): item
            for item in active.preview.candidates
        }
        if active
        else {}
    )
    mutations = (
        {
            (
                item.preview.generated_mutation.endpoint,
                item.preview.generated_mutation.operation_name,
            ): item
            for item in active.executions
        }
        if active
        else {}
    )
    included: list[AIOperation] = []
    for operation in operations:
        if len(included) >= MAX_AI_OPERATIONS:
            break
        name = _identifier(operation.name)
        if name is None:
            continue
        key = (operation.endpoint, name)
        query = queries.get(key) if operation.kind is OperationKind.QUERY else None
        execution = executions.get(key) if operation.kind is OperationKind.QUERY else None
        candidate = candidates.get(key) if operation.kind is OperationKind.MUTATION else None
        mutation = mutations.get(key) if operation.kind is OperationKind.MUTATION else None
        artifact = candidate.generated_mutation if candidate else query
        response = mutation.response if mutation else execution.response if execution else None
        included.append(
            AIOperation(
                operation=f"{endpoints[operation.endpoint]}/{operation.kind.value}/{name}",
                kind=operation.kind,
                name=name,
                return_type=_identifier(operation.return_type.named_type),
                priority=operation.priority,
                interest_score=operation.interest_score,
                categories=operation.categories,
                generated=artifact.success if artifact else False,
                manual_adjustment_required=bool(artifact and artifact.manual_adjustments),
                execution_status=mutation.status
                if mutation
                else execution.status
                if execution
                else None,
                http_status=response.status_code if response else None,
                attempted=mutation.attempted
                if mutation
                else execution.attempted
                if execution
                else False,
                mutation_safety=candidate.decision if candidate else None,
                selectable=candidate.selectable if candidate else False,
                selected=mutation.selected if mutation else False,
                mutation_decision=mutation.decision if mutation else None,
            )
        )
    schemas = []
    for item in schema_scan.schemas:
        summary = item.summary
        if summary and item.endpoint in endpoints:
            schemas.append(
                AISchemaSummary(
                    endpoint=endpoints[item.endpoint],
                    query_root=_identifier(summary.query_root),
                    mutation_root=_identifier(summary.mutation_root),
                    total_types=summary.total_type_count,
                    queries=summary.query_field_count,
                    mutations=summary.mutation_field_count,
                    subscriptions=summary.subscription_field_count,
                )
            )
    schemas_total = len(schemas)
    # Only aggregate numeric facts; never copy error/reason strings into the prompt.
    counts = {
        "schema_parsing_failures": sum(not item.success for item in schema_scan.schemas),
        "introspection_unavailable": sum(
            item.status.value != "enabled" for item in introspection.introspections
        ),
        "query_generation_failures": sum(
            not item.success for item in safe.query_generation.queries
        ),
        "query_requests": sum(
            item.evidence_type is EvidenceType.QUERY_EXECUTION for item in result.evidence
        ),
        "mutation_requests": sum(
            item.evidence_type is EvidenceType.MUTATION_EXECUTION for item in result.evidence
        ),
        "query_count": sum(item.queries for item in schemas),
        "mutation_count": sum(item.mutations for item in schemas),
        "mutation_not_attempted": sum(not item.attempted for item in active.executions)
        if active
        else 0,
    }
    # Count the complete results before truncation. HTTP 200 and an attempted request
    # are not success classifications; skipped operations never enter success totals.
    for status in QueryExecutionStatus:
        counts[f"query_{status.value}"] = sum(item.status is status for item in safe.executions)
        counts[f"mutation_{status.value}"] = (
            sum(item.attempted and item.status is status for item in active.executions)
            if active
            else 0
        )
    schemas = schemas[:10]
    counts.update(
        {
            "deterministic_findings": sum(f.category.value == "finding" for f in security_facts),
            "policy_violations": sum(f.evaluation == "violated" for f in security_facts),
            "policy_satisfied": sum(f.evaluation == "satisfied" for f in security_facts),
            "policy_unresolved": sum(f.evaluation == "unresolved" for f in security_facts),
            "security_observations": sum(
                f.category.value == "security_observation" for f in security_facts
            ),
        }
    )
    while True:
        context = AIContext(
            mode=introspection.detection.discovery.mode,
            final_batch_confirmed=active.confirmed if active else None,
            metadata=AIContextMetadata(
                operations_total=len(operations),
                operations_included=len(included),
                operations_omitted=len(operations) - len(included),
                schemas_total=schemas_total,
                schemas_included=len(schemas),
                security_facts_total=security_facts_total,
                security_facts_included=len(security_facts),
                security_facts_omitted=security_facts_total - len(security_facts),
                deterministic_findings=counts["deterministic_findings"],
                policy_violations=counts["policy_violations"],
                policy_satisfied=counts["policy_satisfied"],
                policy_unresolved=counts["policy_unresolved"],
                context_truncated=(
                    len(included) < len(operations)
                    or len(schemas) < schemas_total
                    or len(security_facts) < security_facts_total
                ),
            ),
            operations=tuple(included),
            schemas=tuple(schemas),
            counts=counts,
            security_facts=tuple(security_facts),
            capability_coverage=coverage,
        )
        # Include the byte-count field itself: converge on its exact serialized digit width.
        while context.metadata.serialized_bytes != len(serialize_context(context).encode("utf-8")):
            size = len(serialize_context(context).encode("utf-8"))
            context = context.model_copy(
                update={"metadata": context.metadata.model_copy(update={"serialized_bytes": size})}
            )
        if len(serialize_context(context).encode("utf-8")) <= MAX_CONTEXT_BYTES:
            return context
        # Security facts have reserved capacity ahead of every ordinary operation.
        if included:
            included.pop()
        elif schemas:
            schemas.pop()
        elif security_facts:
            security_facts.pop()
        else:
            raise ValueError("AI summary exceeds the bounded context size.")
