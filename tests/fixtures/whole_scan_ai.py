"""Project-owned completed results with fake private material for AI boundary tests."""

from dataclasses import replace

from gqlsleuth.application.active_execution import (
    execute_selected_mutations,
    prepare_active_mutations,
)
from gqlsleuth.domain import (
    abuse_controls as abuse,
)
from gqlsleuth.domain import (
    authentication as auth,
)
from gqlsleuth.domain import (
    authorization_policy as policy,
)
from gqlsleuth.domain import (
    federation as fed,
)
from gqlsleuth.domain import (
    file_upload as upload,
)
from gqlsleuth.domain import (
    idor,
)
from gqlsleuth.domain import (
    multiplicity as multi,
)
from gqlsleuth.domain import (
    mutation_authorization as mutation,
)
from gqlsleuth.domain import (
    object_authorization as obj,
)
from gqlsleuth.domain import (
    query_depth as depth,
)
from gqlsleuth.domain import (
    sensitive_input as sensitive,
)
from gqlsleuth.domain import (
    sequential_discovery as seq,
)
from gqlsleuth.domain import (
    subscriptions as sub,
)
from gqlsleuth.domain.execution import QueryExecutionStatus
from gqlsleuth.domain.security_review import SecurityCandidateType

SDL = """
scalar Upload
type Query { lookup(id: ID!): Item login: String items: [Item] }
type Mutation { updateUser(id: ID!, input: Input!): Item upload(file: Upload!): Item }
input Input { ownerId: ID role: String }
type Item { id: ID children: [Item] }
type Subscription { notificationCreated(objectId: ID!): Item }
"""
RAW = "RAW_RESPONSE_SDL_FRAME_ERROR_CANARY"
IDENTIFIER = "OBJECT_SEED_NEIGHBOR_ID_CANARY"
VALUE = "SENSITIVE_BUSINESS_VALUE_CANARY"
VARIABLE = "SUBSCRIPTION_VARIABLE_CANARY"
FILE = "UPLOAD_PATH_FILENAME_BYTES_HASH_CANARY"
TOKEN = "JWT_TOKEN_CLAIMS_SIGNATURE_VARIANT_CANARY"
SECRET = "AUTH_COOKIE_API_PROXY_INIT_CANARY"
CANARIES = (RAW, IDENTIFIER, VALUE, VARIABLE, FILE, TOKEN, SECRET)


def assemble(safe):
    active = execute_selected_mutations(prepare_active_mutations(safe), confirmed=False)
    operations = safe.query_generation.operation_analysis.endpoints[0].operations
    lookup = next(o for o in operations if o.name == "lookup")
    file_op = next(o for o in operations if o.name == "upload")
    generated = next(q for q in safe.query_generation.queries if q.operation_name == "lookup")
    source = safe.query_generation.security_review.candidates[0]
    sources = source.source_evidence_ids
    discovery = (
        safe.query_generation.operation_analysis.schema_scan.introspection.detection.discovery
    )
    target = discovery.target
    endpoint = lookup.endpoint
    base = dict(
        target=target,
        endpoint=endpoint,
        source=RAW,
        summary=RAW,
        query=RAW,
        variables={"private": VARIABLE},
        response_body=RAW.encode(),
        response_headers={"Authorization": SECRET},
        notes=(TOKEN, FILE, VALUE),
    )
    # Phase 17 and 18: accepted shape and scoped rejection, never Findings.
    mpreview = multi.MultiplicityProbePreview(
        multi.MultiplicityProbeType.ALIAS_MULTIPLICITY, generated, RAW, {"private": VARIABLE}
    )
    me = multi.MultiplicityEvidence(
        **base,
        probe_type=mpreview.probe_type,
        representative_operation="lookup",
        multiplicity=3,
        request_json={"private": VARIABLE},
        observation="accepted",
    )
    multiplicity = multi.MultiplicityValidationResult(
        (mpreview,),
        (1,),
        True,
        (
            multi.MultiplicityProbeExecutionResult(
                mpreview, True, multi.MultiplicityDecision.EXECUTED, RAW, me
            ),
        ),
        (),
    )
    dpreview = depth.QueryDepthProbePreview(
        generated, RAW, QueryExecutionStatus.SUCCESS, 2, 4, ("lookup", "children", "id"), 1, sources
    )
    de = depth.QueryDepthEvidence(
        **base,
        representative_operation="lookup",
        baseline_status="success",
        baseline_depth=2,
        probe_depth=4,
        recursive_path=dpreview.recursive_path,
        list_edges=1,
        source_evidence_ids=sources,
        observation="rejected",
    )
    query_depth = depth.QueryDepthValidationResult(
        (dpreview,),
        (1,),
        True,
        (
            depth.QueryDepthExecutionResult(
                dpreview, True, depth.QueryDepthDecision.EXECUTED, RAW, de
            ),
        ),
        (),
    )
    # Anonymous object review and local operator policy.
    case = obj.ObjectAuthorizationCase(
        obj.ObjectAuthorizationMode.ANONYMOUS_ONLY, None, "lookup", "id", IDENTIFIER, 1
    )
    oe = obj.ObjectAuthorizationEvidence(
        **base,
        object_mode=case.mode,
        context="anonymous",
        has_supplied_context_headers=False,
        declared_authorized_context=None,
        root_operation="lookup",
        identifier_argument="id",
        identifier=IDENTIFIER,
        source_evidence_ids=sources,
        outcome="target_returned",
        returned_id_matches=True,
    )
    object_result = obj.ObjectAuthorizationResult(
        case.mode,
        (case,),
        executions=(
            obj.ObjectExecution(
                1, obj.ObjectContext("anonymous", False), True, oe.outcome, True, RAW, oe
            ),
        ),
        attempted_request_count=1,
    )
    assertion = policy.AuthorizationPolicyAssertion(1, 1, "anonymous", True)
    evaluation = policy.AuthorizationPolicyEvaluation(
        assertion, case, oe.outcome, policy.PolicyStatus.VIOLATED, sources, RAW
    )
    policy_result = policy.AuthorizationPolicyResult(
        (assertion,), (evaluation,), (policy.AuthorizationPolicyViolation(evaluation),)
    )
    safe = replace(
        safe,
        object_authorization_review=object_result,
        authorization_policy_validation=policy_result,
    )
    active = replace(active, preview=replace(active.preview, safe_execution=safe))
    # Sequential observations and an existing IDOR Finding; identifiers never leave this fixture.
    seed = seq.SequentialDiscoverySeed("lookup", "id", IDENTIFIER, 1)
    probe = seq.SequentialDiscoveryProbe(
        seed, endpoint, IDENTIFIER, 1, RAW, {"id": IDENTIFIER}, ("lookup", "id"), source, sources
    )
    se = seq.SequentialDiscoveryEvidence(
        **base,
        root_operation="lookup",
        identifier_argument="id",
        operator_seed=IDENTIFIER,
        requested_identifier=IDENTIFIER,
        offset=1,
        has_supplied_context_headers=False,
        source_evidence_ids=sources,
        outcome="target_returned",
        returned_id_matches=True,
    )
    sequential = seq.SequentialDiscoveryResult(
        (seed,),
        (probe,),
        confirmed=True,
        executions=(seq.SequentialDiscoveryExecution(probe, True, se.outcome, True, RAW, se),),
        candidates=(seq.SequentialDiscoveryCandidate(seed, IDENTIFIER, 1, False, sources, RAW),),
        attempted_request_count=1,
    )
    ie = idor.IdorProbeEvidence(
        **base,
        context_type="anonymous",
        context_label=None,
        root_operation="lookup",
        identifier_argument="id",
        operator_seed=IDENTIFIER,
        requested_identifier=IDENTIFIER,
        offset=1,
        role="alternate",
        expected="deny",
        policy_result="violated",
        source_evidence_ids=sources,
        outcome="target_returned",
        returned_id_matches=True,
    )
    idor_result = idor.IdorDetectionResult(
        (seed,),
        idor.IdorContextType.ANONYMOUS,
        probes=(probe,),
        confirmed=True,
        executions=(
            idor.IdorExecution(probe, "alternate", "deny", idor.IdorPolicyResult.VIOLATED, RAW, ie),
        ),
        findings=(
            idor.IdorFinding(
                endpoint,
                "lookup",
                "id",
                IDENTIFIER,
                idor.IdorContextType.ANONYMOUS,
                None,
                RAW,
                ie.evidence_id,
                None,
                sources,
            ),
        ),
        attempted_request_count=1,
    )
    # Mutation and sensitive-input policy violations, intentionally no Finding taxonomy.
    mc = mutation.MutationAuthorizationCase("updateUser", "id", IDENTIFIER)
    mev = mutation.MutationAuthorizationEvaluation(
        policy.PolicyStatus.VIOLATED,
        mutation.MutationAuthorizationOutcome.TARGET_MUTATION_RETURNED,
        RAW,
        sources,
    )
    mutation_result = mutation.MutationAuthorizationResult(
        (mc,),
        probe=mutation.PreparedMutationAuthorizationProbe(
            mc, endpoint, RAW, {"id": IDENTIFIER}, ("updateUser", "id"), sources
        ),
        confirmed=True,
        evaluation=mev,
        violation=mutation.MutationAuthorizationViolation(mev),
        attempted_request_count=1,
    )
    sc = sensitive.SensitiveInputCase(
        "updateUser", "input", "ownerId", VALUE, sensitive.SensitiveInputTarget("id", IDENTIFIER)
    )
    sev = sensitive.SensitiveInputEvaluation(
        policy.PolicyStatus.VIOLATED,
        sensitive.SensitiveInputOutcome.TARGET_VALUE_RETURNED,
        RAW,
        sources,
    )
    sensitive_result = sensitive.SensitiveInputValidationResult(
        sc,
        confirmed=True,
        evaluation=sev,
        violation=sensitive.SensitiveInputViolation(sev),
        attempted_request_count=1,
    )
    # Token metadata is safe; unsafe token strings live only in ignored fields.
    review = auth.TokenSecurityReview(
        "jwt", "HS256", (("kid", True),), (("sub", True),), (("exp", "expired"),), (TOKEN,)
    )
    ae = auth.AuthenticationProbeEvidence(
        **base,
        operation="lookup",
        baseline_evidence_id=sources[0],
        probe_type="jwt_signature_tampered",
        token_review=review,
        outcome="returned",
        policy_result="violated",
    )
    auth_result = auth.AuthenticationSecurityResult(
        review,
        executions=(
            auth.AuthenticationProbeExecution(
                auth.AuthenticationProbe.JWT_SIGNATURE_TAMPERED, RAW, ae
            ),
        ),
        findings=(
            auth.AuthenticationSecurityFinding(
                auth.AuthenticationFindingKind.JWT_SIGNATURE_VALIDATION_FAILURE,
                endpoint,
                "lookup",
                sources[0],
                ae.evidence_id,
                sources[0],
                TOKEN,
                RAW,
            ),
        ),
    )
    # Fixed abuse sequence policy.
    ac = abuse.AbuseControlCandidate(
        1,
        lookup,
        RAW,
        {"password": SECRET},
        sources[0],
        safe.execution_evidence[0].evidence_type,
        QueryExecutionStatus.SUCCESS,
        200,
        5,
    )
    be = abuse.AbuseControlEvidence(
        **base,
        operation=lookup,
        baseline_evidence_id=sources[0],
        baseline_status="success",
        baseline_http_status=200,
        policy_id=sources[0],
        attempt_index=5,
        planned_attempts=5,
        repeat_status="success",
        outcome="no_control_signal",
    )
    abuse_result = abuse.AbuseControlResult(
        (ac,),
        ac,
        sources[0],
        True,
        (be,),
        policy.PolicyStatus.VIOLATED,
        (abuse.AbuseControlFinding(lookup, sources[0], (be.evidence_id,), sources[0], 5, 1, RAW),),
    )
    # Upload variants retain no file metadata in AI.
    uc = upload.FileUploadCase("upload", ("file",))
    file = upload.UploadFileMetadata(FILE, 1, FILE, FILE)
    ue = upload.UploadEvidence(
        **base,
        case=uc,
        probe="mime_mismatch",
        expected="deny",
        file=file,
        operations={"query": RAW, "variables": {"file": FILE}},
        multipart_map={"0": [FILE]},
        variable_path=FILE,
        source_evidence_ids=sources,
        outcome="upload_accepted",
        evaluation="violated",
    )
    upload_result = upload.FileUploadSecurityResult(
        uc,
        plan=upload.UploadPlan(
            uc, file_op, RAW, {"file": FILE}, FILE, {"0": [FILE]}, sources, file
        ),
        selected_variants=(upload.UploadProbe.MIME_MISMATCH,),
        confirmed=True,
        attempts=(ue,),
        baseline_status=upload.UploadBaselineStatus.BASELINE_CONFIRMED,
        findings=(
            upload.UploadFinding(
                uc, file_op, upload.UploadProbe.MIME_MISMATCH, sources[0], ue.evidence_id, RAW
            ),
        ),
    )
    # Federation entity typename/key names may enter; key values/SDL must never do so.
    fp = fed.FederationPlan(
        fed.FederationProbe.ENTITY,
        RAW,
        {"representations": [{"__typename": "Item", "id": IDENTIFIER}]},
        fed.FederationPolicy.DENY,
        (("id", "ID"),),
    )
    fe = fed.FederationEvidence(
        **base,
        probe="entity",
        expected="deny",
        source_candidate=source,
        source_evidence_ids=sources,
        outcome="entity_returned",
        evaluation="violated",
        sdl_sha256=FILE,
    )
    federation_result = fed.FederationSecurityResult(
        (fed.FederationCandidate(endpoint, source, ("Item",), True, True, (fp,)),),
        endpoint,
        (fed.FederationProbe.ENTITY,),
        True,
        (fe,),
        (
            fed.FederationFinding(
                "FEDERATION_ENTITY_AUTHORIZATION_FAILURE",
                RAW,
                endpoint,
                fe.evidence_id,
                sources,
                RAW,
            ),
        ),
    )
    # Subscription event facts, without URL, variables or frame body in AI.
    schema = safe.query_generation.operation_analysis.schema_scan.schemas[0].schema
    sub_source = next(
        c
        for c in safe.query_generation.security_review.candidates
        if c.candidate_type is SecurityCandidateType.SUBSCRIPTION_SURFACE
    )
    field = schema.type_named(schema.subscription_root).fields[0]
    sp = sub.SubscriptionPlan(
        sub.SubscriptionCandidate(
            endpoint, schema.subscription_root, field, sub_source, RAW, {"objectId": VARIABLE}
        ),
        "wss://PRIVATE_WS_URL_CANARY/graphql",
        {"objectId": VARIABLE},
        sub.SubscriptionPolicy.DENY,
        True,
        True,
        42,
    )
    we = sub.SubscriptionEvidence(
        **base,
        plan=sp,
        source_evidence_ids=sources,
        negotiated_protocol="graphql-transport-ws",
        connected=True,
        acknowledged=True,
        subscription_sent=True,
        inbound_frame_count=2,
        application_event_count=1,
        outcome="event_returned",
        evaluation="violated",
    )
    subscriptions = sub.SubscriptionSecurityResult(
        (sp.candidate,),
        sp,
        True,
        (we,),
        (
            sub.SubscriptionFinding(
                endpoint,
                field.name,
                sub.SubscriptionProtocol.MODERN,
                True,
                we.evidence_id,
                sources,
                RAW,
            ),
        ),
    )
    return replace(
        active,
        multiplicity=multiplicity,
        query_depth=query_depth,
        sequential_object_discovery=sequential,
        mutation_authorization=mutation_result,
        sensitive_input_validation=sensitive_result,
        idor_bola_detection=idor_result,
        authentication_token_security=auth_result,
        rate_limiting_abuse_controls=abuse_result,
        file_upload_security=upload_result,
        federation_security=federation_result,
        subscription_security=subscriptions,
    )
