"""One independently confirmed file baseline and bounded, canonical validation probes."""

import base64
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from graphql import GraphQLError

from gqlsleuth.application.mutation_preparation import retained_mutation
from gqlsleuth.application.nested_authorization import exact_variables
from gqlsleuth.application.safe_execution import SafeExecutionScanResult
from gqlsleuth.domain.authorization_policy import PolicyStatus
from gqlsleuth.domain.exceptions import (
    HttpConfigurationError,
    HttpError,
    QueryGenerationError,
    SafeExecutionValidationError,
    SchemaParsingError,
)
from gqlsleuth.domain.file_upload import (
    MAX_PHASE28_REQUESTS,
    UPLOAD_VARIANTS,
    FileUploadCase,
    FileUploadSecurityResult,
    UploadBaselineStatus,
    UploadEvidence,
    UploadExpectedPolicy,
    UploadFinding,
    UploadOutcome,
    UploadPlan,
    UploadProbe,
    parse_upload_case,
)
from gqlsleuth.domain.models import ScanMode
from gqlsleuth.domain.security_review import SecurityCandidateType
from gqlsleuth.graphql.file_upload import build_upload_document, classify_upload_response
from gqlsleuth.graphql.query_generation import generate_mutation
from gqlsleuth.infrastructure.http import (
    HttpClient,
    HttpClientSettings,
    HttpRequest,
    SingleFileMultipart,
)
from gqlsleuth.infrastructure.probe_evidence import (
    capture_probe_response,
    request_context_material,
    same_origin,
)
from gqlsleuth.infrastructure.upload_file import (
    BENIGN_UPLOAD_CONTENT,
    read_upload_file,
    upload_variant,
)


def prepare_file_upload(
    safe: SafeExecutionScanResult,
    *,
    case: FileUploadCase,
    file_path: Path,
    content_type: str | None = None,
    enabled: bool = False,
) -> FileUploadSecurityResult:
    result = FileUploadSecurityResult(case)
    scan = safe.query_generation.operation_analysis.schema_scan
    if enabled is not True or scan.introspection.detection.discovery.mode is not ScanMode.ACTIVE:
        return replace(
            result,
            limitations=("File upload testing requires explicit enablement and ACTIVE mode.",),
        )
    if (
        type(case) is not FileUploadCase
        or type(case.operation) is not str
        or type(case.path) is not tuple
        or not all(type(part) is str for part in case.path)
        or parse_upload_case([case.operation + ":" + ".".join(case.path)]) != case
    ):
        raise HttpConfigurationError("Requires one validated upload case.")
    metadata, _ = read_upload_file(file_path, content_type)
    try:
        schema, native, operation, references = retained_mutation(safe, case.operation)
        review = safe.query_generation.security_review
        sources = tuple(
            candidate
            for candidate in (review.candidates if review else ())
            if candidate.candidate_type is SecurityCandidateType.FILE_UPLOAD_SURFACE
            and candidate.related_operation == operation
            and candidate.endpoint == operation.endpoint
        )
        if (
            not references
            or not sources
            or any(
                not source.source_evidence_ids
                or not set(source.source_evidence_ids).issubset(references)
                for source in sources
            )
        ):
            raise SafeExecutionValidationError(
                "Requires retained Mutation FILE_UPLOAD_SURFACE and schema provenance."
            )
        artifact = generate_mutation(schema, operation)
        query, variables, path = build_upload_document(schema, native, artifact, case)
        return replace(
            result,
            plan=UploadPlan(
                case,
                operation,
                query,
                variables,
                path,
                {"0": [path]},
                references,
                metadata,
                artifact.manual_adjustments,
            ),
        )
    except SafeExecutionValidationError as error:
        return replace(result, limitations=(str(error),))
    except (
        QueryGenerationError,
        SchemaParsingError,
        GraphQLError,
        ValueError,
        TypeError,
        RecursionError,
    ):
        return replace(
            result,
            limitations=(
                "Compatible Upload schema or deterministic Mutation construction is unavailable.",
            ),
        )


def _matches(left: FileUploadSecurityResult, right: FileUploadSecurityResult) -> bool:
    try:
        return (
            type(left) is FileUploadSecurityResult
            and left == right
            and type(left.confirmed) is bool
            and exact_variables(left.plan.operations if left.plan else None)
            == exact_variables(right.plan.operations if right.plan else None)
        )
    except (ValueError, TypeError, RecursionError):
        return False


class FileUploadSecuritySession:
    """Own runtime-only file path/settings; no public plan supplies bytes to the transport."""

    def __init__(
        self,
        safe: SafeExecutionScanResult,
        *,
        case: FileUploadCase,
        file_path: Path,
        content_type: str | None = None,
        enabled: bool = False,
        http_settings: HttpClientSettings | None = None,
    ) -> None:
        self._safe, self._case, self._path = safe, case, file_path
        self._mime, self._enabled = content_type, enabled
        self._settings = http_settings or HttpClientSettings()
        self._settings_snapshot = self._settings.model_dump_json()
        self._selected: tuple[UploadProbe, ...] = ()
        self._preview = self._prepare()
        self._result = self._preview
        self._finished = False
        self._attempts = 0

    def _prepare(self) -> FileUploadSecurityResult:
        return replace(
            prepare_file_upload(
                self._safe,
                case=self._case,
                file_path=self._path,
                content_type=self._mime,
                enabled=self._enabled,
            ),
            selected_variants=self._selected,
        )

    @property
    def preview(self) -> FileUploadSecurityResult:
        return deepcopy(self._preview)

    def select_variants(self, probes: tuple[UploadProbe, ...]) -> FileUploadSecurityResult:
        if self._finished or any(
            type(probe) is not UploadProbe or probe not in UPLOAD_VARIANTS for probe in probes
        ):
            raise HttpConfigurationError("Select only the three listed upload validation variants.")
        self._selected = tuple(probe for probe in UPLOAD_VARIANTS if probe in probes)
        self._preview = replace(self._preview, selected_variants=self._selected)
        return self.preview

    def execute(
        self, *, preview: FileUploadSecurityResult, confirmed: bool = False
    ) -> FileUploadSecurityResult:
        if self._finished:
            return deepcopy(self._result)
        self._finished = True
        plan = self._preview.plan
        self._result = replace(self._preview, confirmed=confirmed is True)
        if confirmed is not True or plan is None:
            return deepcopy(self._result)
        attempts: list[UploadEvidence] = []
        findings = []
        limitations = list(self._preview.limitations)
        baseline = UploadBaselineStatus.NOT_EXECUTED
        for probe in (UploadProbe.BASELINE, *self._selected):
            try:
                fresh = self._prepare()
                metadata, data = read_upload_file(self._path, self._mime)
                valid = (
                    _matches(self._preview, fresh)
                    and _matches(preview, fresh)
                    and fresh.plan is not None
                    and metadata == fresh.plan.baseline
                    and self._settings.model_dump_json() == self._settings_snapshot
                    and self._attempts == len(attempts)
                    and self._attempts < MAX_PHASE28_REQUESTS
                    and (
                        probe is UploadProbe.BASELINE
                        or baseline is UploadBaselineStatus.BASELINE_CONFIRMED
                    )
                )
            except HttpConfigurationError:
                valid = False
            if not valid:
                limitations.append(
                    "File, schema, request context or approved plan changed; "
                    "remaining uploads were not sent."
                )
                break
            self._attempts += 1
            evidence = self._request(plan, probe, data)
            attempts.append(evidence)
            if probe is UploadProbe.BASELINE:
                baseline = (
                    UploadBaselineStatus.BASELINE_CONFIRMED
                    if evidence.outcome is UploadOutcome.UPLOAD_ACCEPTED
                    else UploadBaselineStatus.BASELINE_UNUSABLE
                )
                if baseline is UploadBaselineStatus.BASELINE_UNUSABLE:
                    limitations.append(
                        "Baseline was not confirmed; no validation variants were sent."
                    )
                    break
            elif evidence.evaluation is PolicyStatus.VIOLATED:
                descriptions = {
                    UploadProbe.CONTENT_MISMATCH: (
                        "A fixed benign content mismatch with unchanged filename and MIME"
                    ),
                    UploadProbe.MIME_MISMATCH: (
                        "The baseline file with only its multipart MIME changed"
                    ),
                    UploadProbe.EXTENSION_MISMATCH: (
                        "The baseline file with only a safe alternate filename extension"
                    ),
                }
                findings.append(
                    UploadFinding(
                        plan.case,
                        plan.operation,
                        probe,
                        attempts[0].evidence_id,
                        evidence.evidence_id,
                        descriptions[probe]
                        + " was accepted despite the operator-supplied DENY expectation.",
                    )
                )
        self._result = replace(
            self._result,
            attempts=tuple(attempts),
            baseline_status=baseline,
            findings=tuple(findings),
            limitations=tuple(limitations),
        )
        return deepcopy(self._result)

    def _request(
        self, plan: UploadPlan, probe: UploadProbe, baseline_data: bytes
    ) -> UploadEvidence:
        file, data = upload_variant(plan.baseline, baseline_data, probe)
        timestamp, started = datetime.now(UTC), perf_counter()
        response = None
        error_type = None
        try:
            with HttpClient(self._settings) as client:
                response = client.send(
                    HttpRequest(
                        method="POST",
                        url=plan.operation.endpoint,
                        multipart=SingleFileMultipart(
                            {
                                "operations": json.dumps(plan.operations, sort_keys=True),
                                "map": json.dumps(plan.multipart_map, sort_keys=True),
                            },
                            file.filename,
                            file.content_type,
                            data,
                        ),
                    )
                )
        except HttpError as error:
            error_type = type(error).__name__
            outcome = UploadOutcome.NETWORK_FAILURE
        else:
            outcome = classify_upload_response(response.status_code, response.body, plan.case)
            if not same_origin(plan.operation.endpoint, response.final_url):
                outcome = UploadOutcome.INDETERMINATE
        evaluation: PolicyStatus | UploadBaselineStatus
        if probe is UploadProbe.BASELINE:
            evaluation = (
                UploadBaselineStatus.BASELINE_CONFIRMED
                if outcome is UploadOutcome.UPLOAD_ACCEPTED
                else UploadBaselineStatus.BASELINE_UNUSABLE
            )
        else:
            evaluation = (
                PolicyStatus.VIOLATED
                if outcome is UploadOutcome.UPLOAD_ACCEPTED
                else PolicyStatus.SATISFIED
                if outcome is UploadOutcome.EXPLICIT_FILE_REJECTION
                else PolicyStatus.UNRESOLVED
            )
        # Upload bytes/path are runtime material, including when a target echoes them.
        material = (
            *request_context_material(self._settings),
            str(self._path),
            str(self._path.absolute()),
            str(self._path.parent),
            str(self._path.absolute().parent),
            *(
                text
                for content in (baseline_data, BENIGN_UPLOAD_CONTENT)
                for text in (
                    content.decode("utf-8", errors="replace"),
                    base64.b64encode(content).decode(),
                )
            ),
        )
        headers, body, withheld = capture_probe_response(
            response, tuple(v for v in material if v and v != ".")
        )
        schema_scan = self._safe.query_generation.operation_analysis.schema_scan
        discovery = schema_scan.introspection.detection.discovery
        return UploadEvidence(
            target=discovery.target,
            endpoint=plan.operation.endpoint,
            timestamp=timestamp,
            source="gqlsleuth.application.file_upload",
            summary=f"File upload: {probe.value}; {outcome.value}.",
            case=plan.case,
            probe=probe,
            expected=UploadExpectedPolicy.ALLOW
            if probe is UploadProbe.BASELINE
            else UploadExpectedPolicy.DENY,
            file=file,
            operations=deepcopy(plan.operations),
            multipart_map=deepcopy(plan.multipart_map),
            variable_path=plan.variable_path,
            source_evidence_ids=plan.source_evidence_ids,
            query=plan.query,
            variables=deepcopy(plan.variables),
            request_method="POST",
            outcome=outcome,
            evaluation=evaluation,
            response_material_withheld=withheld,
            response_status_code=response.status_code if response else None,
            response_headers=headers,
            response_body=body,
            duration_seconds=response.duration_seconds if response else perf_counter() - started,
            error_type=error_type,
            error_message="Target upload transport failed." if error_type else None,
        )
