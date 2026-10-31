"""Sequential, budgeted recovery; original responses never masquerade as local assembly."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from time import monotonic

from pydantic import JsonValue

from gqlsleuth.domain.exceptions import HttpError, ResponseTooLargeError
from gqlsleuth.graphql.introspection import (
    IntrospectionResponseClassification,
    IntrospectionStatus,
    SchemaRetrievalStatus,
    classify_introspection_response,
    reduced_introspection_fallback_reason,
)
from gqlsleuth.graphql.introspection_compatibility import (
    QUERY_ARGUMENTS,
    compatible_query,
    deprecated_coverage_note,
    unsupported_optional_arguments,
)
from gqlsleuth.graphql.progressive_introspection import (
    CATALOGUE_QUERY,
    DIRECTIVES_QUERY,
    MAX_RECOVERY_QUERY_BYTES,
    ROOT_INVENTORY_QUERY,
    TYPE_QUERIES,
    AssembledSchema,
    RecoveredType,
    RecoveryCatalogue,
    RecoveryDataError,
    assemble_schema,
    object_value,
    parse_catalogue,
    parse_type,
)
from gqlsleuth.graphql.response_json import response_json_object
from gqlsleuth.infrastructure.http import HttpClient, HttpRequest, HttpResponse

MAX_PROGRESSIVE_REQUESTS = 32
MAX_PROGRESSIVE_SECONDS = 60.0
MAX_PROGRESSIVE_RESPONSE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class RecoveryAttempt:
    shape: str
    query: str
    variables: dict[str, JsonValue]
    timestamp: datetime
    response: HttpResponse | None
    error_type: str | None = None
    error_message: str | None = None
    omitted_arguments: tuple[str, ...] = ()
    unsupported_arguments: tuple[str, ...] = ()

    @property
    def classification(self) -> str:
        """Classify the retained response envelope, not schema completeness."""
        if self.response is None:
            return self.error_type or "No response"
        if self.unsupported_arguments:
            return "unsupported_introspection_argument"
        response = self.response
        restriction = reduced_introspection_fallback_reason(response.status_code, response.body)
        if restriction:
            return restriction.value
        document = response_json_object(response.body)
        if (
            200 <= response.status_code < 300
            and document is not None
            and ("errors" not in document or document["errors"] == [])
            and isinstance(document.get("data"), dict)
        ):
            return "data_received"
        status = classify_introspection_response(response.status_code, response.body).status
        return (
            IntrospectionStatus.ENDPOINT_ERROR.value
            if status is IntrospectionStatus.ENABLED
            else status.value
        )


@dataclass(frozen=True)
class ProgressiveRecoveryResult:
    attempts: tuple[RecoveryAttempt, ...]
    catalogue: RecoveryCatalogue | None
    types: tuple[RecoveredType, ...]
    assembled: AssembledSchema | None
    limitation: str | None
    last_result: IntrospectionResponseClassification
    stop_reason: str = "Incomplete type references"
    compatibility_omissions: tuple[str, ...] = ()
    structurally_validated: bool = False

    @property
    def status(self) -> SchemaRetrievalStatus:
        if self.assembled is not None:
            return SchemaRetrievalStatus.RETRIEVED
        if self.catalogue is not None:
            return SchemaRetrievalStatus.PARTIAL
        return (
            SchemaRetrievalStatus.FAILED
            if self.last_result.status
            in {IntrospectionStatus.NETWORK_FAILURE, IntrospectionStatus.INVALID_RESPONSE}
            else SchemaRetrievalStatus.BLOCKED
        )

    @property
    def summary(self) -> str:
        request_count = len(self.attempts)
        text = (
            f"Progressive recovery: {request_count} "
            f"request{'s' if request_count != 1 else ''}; {self.status.value.upper()}. "
        )
        if self.catalogue:
            roots = dict(self.catalogue.roots)
            types = {t.name: t for t in self.types}
            for role, label in (
                ("queryType", "Queries"),
                ("mutationType", "Mutations"),
                ("subscriptionType", "Subscriptions"),
            ):
                name = roots.get(role)
                item = types.get(name) if name else None
                count = (
                    "0"
                    if name is None
                    else str(len(item.field_names))
                    if item and item.field_names is not None
                    else "Unknown"
                )
                text += f"Known {label}: {count}; "
            unresolved = sum(
                name not in types or not types[name].complete
                for name, _ in self.catalogue.types
                if not name.startswith("__")
            )
            text += f"unresolved/incomplete catalogued types: {unresolved}. "
        text += (
            "Locally assembled schema passed strict validation; "
            "schema-dependent analysis is available."
            if self.assembled
            else "Incomplete recovery; automatic Query generation/execution is unavailable."
        )
        if self.limitation:
            text += " " + self.limitation
        if self.compatibility_omissions:
            text += " " + deprecated_coverage_note(self.compatibility_omissions)
        return text

    @property
    def inventory_notes(self) -> tuple[str, ...]:
        if self.catalogue is None:
            return ()
        types = {t.name: t for t in self.types}
        notes = []
        for role, name in self.catalogue.roots:
            notes.append(f"Recovered {role}: {name or 'none'}")
            item = types.get(name) if name else None
            if item and item.field_names is not None:
                listed = ", ".join(item.field_names[:8])
                notes.append(
                    f"{role} field inventory (showing {min(8, len(item.field_names))} "
                    f"of {len(item.field_names)}): {listed}"
                )
        return tuple(notes)


def recover_schema(endpoint: str, client: HttpClient) -> ProgressiveRecoveryResult:
    """Run only after caller verifies both prior query-shape rejections."""
    started = monotonic()
    attempts: list[RecoveryAttempt] = []
    retained_bytes = 0
    stopped = False
    limitation = None
    stop_reason = "Incomplete type references"
    restriction = None
    unsupported: set[str] = set()
    used_omissions: set[str] = set()
    last = IntrospectionResponseClassification(
        IntrospectionStatus.ENDPOINT_ERROR, "Recovery budget exhausted."
    )

    def send_request(
        shape: str,
        query: str,
        name: str | None,
        available: frozenset[str],
        omissions: tuple[str, ...],
    ) -> tuple[dict[str, object] | None, bool]:
        nonlocal retained_bytes, stopped, limitation, last, stop_reason, restriction
        budget_reason = (
            "Request budget exhausted"
            if len(attempts) >= MAX_PROGRESSIVE_REQUESTS
            else "Recovery time budget exhausted"
            if monotonic() - started >= MAX_PROGRESSIVE_SECONDS
            else "Aggregate response budget exhausted"
            if retained_bytes + client.settings.max_response_body_bytes
            > MAX_PROGRESSIVE_RESPONSE_BYTES
            else None
        )
        if budget_reason:
            stopped = True
            stop_reason = budget_reason
            limitation = budget_reason + "."
            return None, False
        if len(query.encode()) > MAX_RECOVERY_QUERY_BYTES:
            raise ValueError("Static recovery query exceeds its local size bound.")
        variables: dict[str, JsonValue] = {"name": name} if name else {}
        timestamp = datetime.now(UTC)
        try:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=endpoint,
                    json_body={"query": query, **({"variables": variables} if variables else {})},
                )
            )
        except HttpError as error:
            attempts.append(
                RecoveryAttempt(
                    shape,
                    query,
                    variables,
                    timestamp,
                    None,
                    type(error).__name__,
                    str(error),
                    omitted_arguments=omissions,
                )
            )
            used_omissions.update(omissions)
            stopped = True
            stop_reason = (
                "Response size limit"
                if isinstance(error, ResponseTooLargeError)
                else "Transport failure"
            )
            limitation = f"Progressive request failed with {type(error).__name__}."
            last = IntrospectionResponseClassification(
                IntrospectionStatus.NETWORK_FAILURE, limitation
            )
            return None, False
        attempts.append(
            RecoveryAttempt(
                shape, query, variables, timestamp, response, omitted_arguments=omissions
            )
        )
        used_omissions.update(omissions)
        retained_bytes += len(response.body)
        rejected = unsupported_optional_arguments(response.status_code, response.body, available)
        if rejected:
            unsupported.update(rejected)
            attempts[-1] = replace(attempts[-1], unsupported_arguments=tuple(sorted(rejected)))
            last = IntrospectionResponseClassification(
                IntrospectionStatus.ENDPOINT_ERROR, "Unsupported optional introspection argument."
            )
            return None, False
        eligible = reduced_introspection_fallback_reason(response.status_code, response.body)
        if eligible is not None:
            restriction = eligible.value.replace("_", " ").capitalize()
            last = IntrospectionResponseClassification(
                IntrospectionStatus.ENDPOINT_ERROR,
                f"Progressive query rejected by {eligible.value}.",
            )
            return None, True
        document = response_json_object(response.body)
        if (
            not 200 <= response.status_code < 300
            or document is None
            or ("errors" in document and document["errors"] != [])
        ):
            stopped = True
            last = classify_introspection_response(response.status_code, response.body)
            if last.status is IntrospectionStatus.ENABLED:
                last = IntrospectionResponseClassification(
                    IntrospectionStatus.ENDPOINT_ERROR, "Progressive response was not successful."
                )
            stop_reason = (
                "Access denied"
                if last.status
                in {
                    IntrospectionStatus.AUTHENTICATION_REQUIRED,
                    IntrospectionStatus.AUTHORIZATION_DENIED,
                }
                else "Introspection disabled"
                if last.status is IntrospectionStatus.DISABLED
                else "Rate limited"
                if response.status_code == 429
                else "Server error"
                if response.status_code >= 500
                else "Malformed GraphQL response"
                if document is None or last.status is IntrospectionStatus.INVALID_RESPONSE
                else "Noneligible response"
            )
            limitation = (
                f"{stop_reason}; recovery stopped at {shape} (HTTP {response.status_code})."
            )
            return None, False
        try:
            data = object_value(document.get("data"))
        except RecoveryDataError:
            stopped = True
            stop_reason = "Malformed GraphQL response"
            last = IntrospectionResponseClassification(
                IntrospectionStatus.INVALID_RESPONSE, "Progressive response has no data object."
            )
            limitation = last.reason
            return None, False
        last = IntrospectionResponseClassification(
            IntrospectionStatus.ENABLED, "Progressive response data retained."
        )
        return data, False

    def request(
        shape: str, query: str, name: str | None = None
    ) -> tuple[dict[str, object] | None, bool]:
        # Only new, exactly identified omissions can advance this loop. At most five
        # capabilities can be learned per recovery; every dispatch uses the shared budgets.
        while True:
            known = frozenset(unsupported)
            variant, omissions = compatible_query(query, unsupported)
            variant_shape = shape + (
                "_legacy_" + "_".join(k.split(".")[1] for k in omissions) if omissions else ""
            )
            data, eligible = send_request(
                variant_shape,
                variant,
                name,
                QUERY_ARGUMENTS.get(query, frozenset()) - known,
                omissions,
            )
            if stopped or known == unsupported:
                return data, eligible

    catalogue = None
    types: dict[str, RecoveredType] = {}
    assembled = None
    structurally_validated = False
    try:
        data, _ = request("catalogue", CATALOGUE_QUERY)
        if data is not None:
            catalogue = parse_catalogue(data)
            kinds = dict(catalogue.types)
            pending = list(dict.fromkeys(name for _, name in catalogue.roots if name in kinds))
            processed: set[str] = set()
            root_names = set(pending)
            # Preserve usable root names before a deeper request can legitimately stop recovery.
            inventory_shape, inventory_query = "root_inventory", ROOT_INVENTORY_QUERY
            for name in pending:
                data, eligible = request(inventory_shape, inventory_query, name)
                if data is not None:
                    types[name] = parse_type(data, name, catalogue)
                elif eligible:
                    # The shallowest predefined shape was rejected. Do not probe deeper.
                    processed.add(name)
                if stopped:
                    break
            # Prioritize verified root identities, then root inputs/outputs, then other types.
            while not stopped:
                if not pending:
                    pending = sorted(
                        name
                        for name in kinds
                        if name not in processed and not name.startswith("__")
                    )
                if not pending:
                    break
                name = pending.pop(0)
                if name in processed:
                    continue
                processed.add(name)
                shapes = TYPE_QUERIES[:-1] if name in root_names else TYPE_QUERIES
                for shape, query in shapes:
                    data, eligible = request(shape, query, name)
                    if data is not None:
                        recovered = parse_type(data, name, catalogue)
                        prior = types.get(name)
                        if prior and prior.field_names != recovered.field_names:
                            if (
                                "__Type.fields" in attempts[-1].omitted_arguments
                                and prior.field_names is not None
                                and recovered.field_names is not None
                                and set(recovered.field_names) < set(prior.field_names)
                            ):
                                # Preserve observed names without fabricating definitions.
                                recovered = replace(
                                    recovered, field_names=prior.field_names, complete=False
                                )
                            else:
                                types[name] = replace(prior, field_names=None)
                                raise RecoveryDataError(
                                    "Type details contradict the recovered root field inventory."
                                )
                        types[name] = recovered
                        references = (*recovered.input_references, *recovered.output_references)
                        pending.extend(
                            ref
                            for ref in references
                            if ref in kinds
                            and ref not in processed
                            and ref not in pending
                            and not ref.startswith("__")
                        )
                        break
                    if stopped or not eligible:
                        break
                # Exhausting eligible shapes is local to this type. Retain prior facts and
                # continue other known types; processed prevents any repeat or infinite loop.
                if stopped:
                    break
            expected = {name for name in kinds if not name.startswith("__")}
            if (
                not stopped
                and catalogue.complete
                and set(types) == expected
                and all(t.complete for t in types.values())
            ):
                data, _ = request("directives", DIRECTIVES_QUERY)
                if data is not None:
                    directives = object_value(data.get("__schema")).get("directives")
                    assembled = assemble_schema(catalogue, tuple(types.values()), directives)
                    structurally_validated = assembled is not None
                    if assembled is not None and used_omissions:
                        # Valid syntax/structure cannot prove deprecated-element coverage.
                        # Preserve the existing prohibition on executing partial recovery.
                        assembled = None
                        stop_reason = "Deprecated-element coverage incomplete"
                        limitation = (
                            "Legacy schema structure validated; exhaustive coverage is unproven."
                        )
            if assembled is None and limitation is None:
                stop_reason = restriction or "Incomplete type references"
                limitation = "Catalogue, type references or directive coverage remains incomplete."
            elif assembled is not None:
                stop_reason = "Complete reconstruction"
        elif limitation is None:
            stop_reason = restriction or "No eligible fallback"
            limitation = "Catalogue unavailable; no further recovery requests."
    except RecoveryDataError as error:
        stop_reason = "Malformed or inconsistent schema data"
        limitation = str(error)
        last = IntrospectionResponseClassification(IntrospectionStatus.INVALID_RESPONSE, limitation)
    return ProgressiveRecoveryResult(
        tuple(attempts),
        catalogue,
        tuple(types.values()),
        assembled,
        limitation,
        last,
        stop_reason,
        tuple(sorted(used_omissions)),
        structurally_validated,
    )
