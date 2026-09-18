"""Small exact normalized-name rules; no substring or recursive input matching."""

from gqlsleuth.domain.sensitive_input import SensitiveInputCategory
from gqlsleuth.rules.operation_analysis import normalize_terms

_GROUPS = {
    SensitiveInputCategory.PRIVILEGE_CONTROL: (
        "admin",
        "isAdmin",
        "staff",
        "isStaff",
        "role",
        "roles",
        "permission",
        "permissions",
        "privilege",
        "privileges",
        "accessLevel",
    ),
    SensitiveInputCategory.OWNERSHIP_CONTROL: ("ownerId", "userId", "accountId"),
    SensitiveInputCategory.TENANCY_CONTROL: ("tenantId", "organizationId", "orgId"),
    SensitiveInputCategory.TRUST_STATE: (
        "verified",
        "isVerified",
        "approved",
        "isApproved",
        "enabled",
        "isEnabled",
    ),
}
_RULES = {normalize_terms(name): category for category, names in _GROUPS.items() for name in names}


def sensitive_category(name: str) -> SensitiveInputCategory | None:
    return _RULES.get(normalize_terms(name))
