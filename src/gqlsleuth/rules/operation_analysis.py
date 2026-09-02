"""Deterministically classify root operations from project-owned schema models."""

import re
from dataclasses import dataclass

from gqlsleuth.domain.analysis import (
    OPERATION_KIND_RANK,
    PRIORITY_RANK,
    OperationAnalysis,
    OperationCategory,
    OperationKind,
    OperationRule,
    RuleMatch,
    RuleSet,
)
from gqlsleuth.domain.exceptions import OperationAnalysisError
from gqlsleuth.domain.schema import ParsedSchema, SchemaField, SchemaNamedType, SchemaTypeKind

_LOWER_OR_DIGIT_TO_UPPER = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM_TO_WORD = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_NON_ALPHANUMERIC = re.compile(r"[^A-Za-z0-9]+")


@dataclass(frozen=True)
class _AnalysisSurface:
    location: str
    tokens: frozenset[str]


def normalize_terms(value: str) -> tuple[str, ...]:
    """Tokenize identifiers and text for exact, case-insensitive rule matching."""
    separated = _LOWER_OR_DIGIT_TO_UPPER.sub(" ", value)
    separated = _ACRONYM_TO_WORD.sub(" ", separated)
    separated = _NON_ALPHANUMERIC.sub(" ", separated)
    return tuple(part.casefold() for part in separated.split() if part)


def analyze_schema_operations(
    endpoint: str,
    schema: ParsedSchema,
    rules: RuleSet,
) -> tuple[OperationAnalysis, ...]:
    """Analyze Query and Mutation root fields using shallow deterministic surfaces."""
    operations: list[OperationAnalysis] = []
    operations.extend(
        _analyze_root(endpoint, schema, schema.query_root, OperationKind.QUERY, rules)
    )
    if schema.mutation_root is not None:
        operations.extend(
            _analyze_root(endpoint, schema, schema.mutation_root, OperationKind.MUTATION, rules)
        )
    return sort_operation_analyses(operations)


def sort_operation_analyses(
    operations: list[OperationAnalysis] | tuple[OperationAnalysis, ...],
) -> tuple[OperationAnalysis, ...]:
    """Sort operations by explicit priority, score, kind, and field name."""
    return tuple(
        sorted(
            operations,
            key=lambda operation: (
                PRIORITY_RANK[operation.priority],
                -operation.interest_score,
                OPERATION_KIND_RANK[operation.kind],
                operation.name.casefold(),
                operation.name,
            ),
        )
    )


def _analyze_root(
    endpoint: str,
    schema: ParsedSchema,
    root_name: str,
    kind: OperationKind,
    rules: RuleSet,
) -> list[OperationAnalysis]:
    root = schema.type_named(root_name)
    if root is None or root.kind is not SchemaTypeKind.OBJECT:
        raise OperationAnalysisError(f"{kind.value.title()} root '{root_name}' is not available.")
    return [_analyze_field(endpoint, schema, field, kind, rules) for field in root.fields]


def _analyze_field(
    endpoint: str,
    schema: ParsedSchema,
    field: SchemaField,
    kind: OperationKind,
    rules: RuleSet,
) -> OperationAnalysis:
    surfaces = _build_surfaces(schema, field)
    matches = tuple(
        match for rule in rules.rules if (match := _match_rule(rule, surfaces)) is not None
    )
    score = sum(match.weight for match in matches)
    if matches:
        category_order = {category: index for index, category in enumerate(OperationCategory)}
        categories = tuple(
            sorted({match.category for match in matches}, key=category_order.__getitem__)
        )
    else:
        categories = (
            OperationCategory.READ_ONLY_BUSINESS_DATA
            if kind is OperationKind.QUERY
            else OperationCategory.STATE_CHANGING_BUSINESS_OPERATION,
        )
    return OperationAnalysis(
        endpoint=endpoint,
        kind=kind,
        name=field.name,
        return_type=field.type,
        categories=categories,
        interest_score=score,
        priority=rules.thresholds.priority_for(score),
        matched_rules=matches,
        reasons=tuple(match.reason for match in matches),
    )


def _build_surfaces(schema: ParsedSchema, field: SchemaField) -> tuple[_AnalysisSurface, ...]:
    surfaces: list[_AnalysisSurface] = []
    _add_surface(surfaces, "operation.name", field.name)
    _add_surface(surfaces, "description", field.description)
    for argument in field.arguments:
        _add_surface(surfaces, f"argument.{argument.name}", argument.name)
        _add_surface(surfaces, f"argument_description.{argument.name}", argument.description)
        argument_type_name = argument.type.named_type
        _add_surface(surfaces, f"argument_type.{argument_type_name}", argument_type_name)
        argument_type = schema.type_named(argument_type_name)
        if argument_type is not None and argument_type.kind is SchemaTypeKind.INPUT_OBJECT:
            for input_field in argument_type.input_fields:
                _add_surface(surfaces, f"input_field.{input_field.name}", input_field.name)
                _add_surface(
                    surfaces,
                    f"input_field_description.{input_field.name}",
                    input_field.description,
                )
                input_type_name = input_field.type.named_type
                _add_surface(
                    surfaces,
                    f"input_field_type.{input_type_name}",
                    input_type_name,
                )

    return_type_name = field.type.named_type
    _add_surface(surfaces, f"return_type.{return_type_name}", return_type_name)
    return_type = schema.type_named(return_type_name)
    if return_type is not None and return_type.kind in {
        SchemaTypeKind.OBJECT,
        SchemaTypeKind.INTERFACE,
    }:
        _add_output_fields(surfaces, return_type)
    return tuple(surfaces)


def _add_output_fields(
    surfaces: list[_AnalysisSurface],
    return_type: SchemaNamedType,
) -> None:
    for returned_field in return_type.fields:
        _add_surface(surfaces, f"return_field.{returned_field.name}", returned_field.name)
        _add_surface(
            surfaces,
            f"return_field_description.{returned_field.name}",
            returned_field.description,
        )
        returned_type_name = returned_field.type.named_type
        _add_surface(
            surfaces,
            f"return_field_type.{returned_type_name}",
            returned_type_name,
        )


def _add_surface(
    surfaces: list[_AnalysisSurface],
    location: str,
    value: str | None,
) -> None:
    if not value:
        return
    tokens = frozenset(normalize_terms(value))
    if tokens:
        surfaces.append(_AnalysisSurface(location=location, tokens=tokens))


def _match_rule(
    rule: OperationRule,
    surfaces: tuple[_AnalysisSurface, ...],
) -> RuleMatch | None:
    matched_keywords: set[str] = set()
    matched_locations: set[str] = set()
    for keyword in rule.keywords:
        keyword_tokens = frozenset(normalize_terms(keyword))
        if not keyword_tokens:
            continue
        for surface in surfaces:
            if keyword_tokens.issubset(surface.tokens):
                matched_keywords.add(keyword.casefold())
                matched_locations.add(surface.location)
    if not matched_keywords:
        return None
    return RuleMatch(
        rule_id=rule.id,
        category=rule.category,
        weight=rule.weight,
        matched_keywords=tuple(sorted(matched_keywords)),
        locations=tuple(sorted(matched_locations)),
        reason=rule.reason,
    )
