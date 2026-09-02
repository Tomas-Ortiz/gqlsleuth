"""Project-owned, immutable representation of a parsed GraphQL schema."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Self


class SchemaTypeKind(StrEnum):
    """Named GraphQL type kinds represented by the Phase 6 schema model."""

    OBJECT = "object"
    INPUT_OBJECT = "input_object"
    SCALAR = "scalar"
    ENUM = "enum"
    INTERFACE = "interface"
    UNION = "union"


class TypeReferenceKind(StrEnum):
    """GraphQL named, list, and non-null type-reference nodes."""

    NAMED = "named"
    LIST = "list"
    NON_NULL = "non_null"


@dataclass(frozen=True)
class TypeReference:
    """Recursive GraphQL type reference that preserves list and nullability wrappers."""

    kind: TypeReferenceKind
    name: str | None = None
    of_type: Self | None = None

    @classmethod
    def named(cls, name: str) -> Self:
        return cls(kind=TypeReferenceKind.NAMED, name=name)

    @classmethod
    def list_of(cls, item_type: Self) -> Self:
        return cls(kind=TypeReferenceKind.LIST, of_type=item_type)

    @classmethod
    def non_null(cls, nullable_type: Self) -> Self:
        return cls(kind=TypeReferenceKind.NON_NULL, of_type=nullable_type)

    @property
    def named_type(self) -> str:
        """Return the base named type below any list/non-null wrappers."""
        if self.kind is TypeReferenceKind.NAMED and self.name is not None:
            return self.name
        if self.of_type is not None:
            return self.of_type.named_type
        raise ValueError("Type reference does not contain a named type.")

    @property
    def outer_non_null(self) -> bool:
        """Whether the outermost wrapper is non-null."""
        return self.kind is TypeReferenceKind.NON_NULL

    @property
    def is_list(self) -> bool:
        """Whether this reference is a list after removing an outer non-null wrapper."""
        reference = self.of_type if self.outer_non_null else self
        return reference is not None and reference.kind is TypeReferenceKind.LIST

    @property
    def list_item(self) -> Self | None:
        """Return the list item reference after removing an outer non-null wrapper."""
        reference = self.of_type if self.outer_non_null else self
        if reference is None or reference.kind is not TypeReferenceKind.LIST:
            return None
        return reference.of_type

    def render(self) -> str:
        """Render the reference using deterministic GraphQL type syntax."""
        if self.kind is TypeReferenceKind.NAMED:
            return self.named_type
        if self.of_type is None:
            raise ValueError("Wrapped type reference is missing its inner type.")
        if self.kind is TypeReferenceKind.LIST:
            return f"[{self.of_type.render()}]"
        return f"{self.of_type.render()}!"


@dataclass(frozen=True)
class SchemaArgument:
    """Argument accepted by a field or directive."""

    name: str
    type: TypeReference
    description: str | None = None
    default_value: str | None = None


@dataclass(frozen=True)
class SchemaInputField:
    """Field declared by an input-object type."""

    name: str
    type: TypeReference
    description: str | None = None
    default_value: str | None = None


@dataclass(frozen=True)
class SchemaField:
    """Field declared by an object or interface type."""

    name: str
    type: TypeReference
    arguments: tuple[SchemaArgument, ...] = ()
    description: str | None = None
    is_deprecated: bool = False
    deprecation_reason: str | None = None


@dataclass(frozen=True)
class SchemaEnumValue:
    """One value declared by an enum type."""

    name: str
    description: str | None = None
    is_deprecated: bool = False
    deprecation_reason: str | None = None


@dataclass(frozen=True)
class SchemaNamedType:
    """One application-facing named GraphQL type and its direct relationships."""

    name: str
    kind: SchemaTypeKind
    description: str | None = None
    fields: tuple[SchemaField, ...] = ()
    input_fields: tuple[SchemaInputField, ...] = ()
    enum_values: tuple[SchemaEnumValue, ...] = ()
    interfaces: tuple[str, ...] = ()
    possible_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class SchemaDirective:
    """Directive definition naturally available in an introspection response."""

    name: str
    locations: tuple[str, ...]
    arguments: tuple[SchemaArgument, ...] = ()
    description: str | None = None


@dataclass(frozen=True)
class SchemaSummary:
    """Deterministic high-level counts for one application schema."""

    query_root: str
    mutation_root: str | None
    subscription_root: str | None
    total_type_count: int
    object_type_count: int
    input_object_type_count: int
    scalar_type_count: int
    custom_scalar_type_count: int
    enum_type_count: int
    interface_type_count: int
    union_type_count: int
    directive_count: int
    query_field_count: int
    mutation_field_count: int
    subscription_field_count: int


@dataclass(frozen=True)
class ParsedSchema:
    """GraphQL schema detached from both raw JSON and graphql-core objects."""

    query_root: str
    mutation_root: str | None
    subscription_root: str | None
    types: tuple[SchemaNamedType, ...]
    directives: tuple[SchemaDirective, ...]
    summary: SchemaSummary

    def type_named(self, name: str) -> SchemaNamedType | None:
        """Find one represented type by its GraphQL name."""
        return next((schema_type for schema_type in self.types if schema_type.name == name), None)
