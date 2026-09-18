"""Zero-request, one-input-level Mutation field discovery and structural-only handoff hints."""

from gqlsleuth.application.operation_analysis import OperationAnalysisScanResult
from gqlsleuth.domain.exceptions import SafeExecutionValidationError
from gqlsleuth.domain.schema import SchemaTypeKind
from gqlsleuth.domain.sensitive_input import SensitiveInputCandidate
from gqlsleuth.graphql.sensitive_input import sensitive_shape
from gqlsleuth.rules.sensitive_input import sensitive_category


def review_sensitive_inputs(
    analysis: OperationAnalysisScanResult,
) -> tuple[SensitiveInputCandidate, ...]:
    candidates = []
    for item in sorted(analysis.schema_scan.schemas, key=lambda item: item.endpoint):
        schema = item.schema
        if not item.success or schema is None or schema.mutation_root is None:
            continue
        root = schema.type_named(schema.mutation_root)
        if root is None:
            continue
        for operation in sorted(root.fields, key=lambda field: field.name):
            for argument in sorted(operation.arguments, key=lambda arg: arg.name):
                input_type = schema.type_named(argument.type.named_type)
                if (
                    argument.type.is_list
                    or input_type is None
                    or input_type.kind is not SchemaTypeKind.INPUT_OBJECT
                ):
                    continue
                for field in sorted(input_type.input_fields, key=lambda field: field.name):
                    category = sensitive_category(field.name)
                    named = schema.type_named(field.type.named_type)
                    if (
                        category is None
                        or named is None
                        or named.kind not in {SchemaTypeKind.SCALAR, SchemaTypeKind.ENUM}
                    ):
                        continue
                    case_template = target_template = None
                    try:
                        shape = sensitive_shape(schema, operation.name, argument.name, field.name)
                        case_template = f"{operation.name}:{argument.name}.{field.name}=<VALUE>"
                        if shape.target_argument:
                            target_template = f"{shape.target_argument}=<ID>"
                    except SafeExecutionValidationError:
                        pass  # Retain the local review candidate, without an incompatible hint.
                    candidates.append(
                        SensitiveInputCandidate(
                            item.endpoint,
                            operation.name,
                            argument.name,
                            field.name,
                            field.type.render(),
                            category,
                            f"Exact normalized {category.value.replace('_', ' ')} input name; "
                            "review server-side field authorization.",
                            (
                                f"Mutation root: {schema.mutation_root}.{operation.name}",
                                f"Input field: {input_type.name}.{field.name}",
                            ),
                            case_template,
                            target_template,
                        )
                    )
    return tuple(candidates)
