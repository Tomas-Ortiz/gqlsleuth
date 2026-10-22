"""Collection budgets for post-scan human views, never ACTIVE consent previews."""

MAX_HUMAN_INVENTORY_ITEMS = 20
MAX_HUMAN_DETAIL_ITEMS = 10
JSON_DETAIL_NOTICE = (
    "Human output omits routine detail. Full inventories and retained request/response "
    "evidence are available in the canonical JSON report."
)


def showing_notice(shown: int, total: int, collection: str) -> str:
    return (
        f"Showing {shown} of {total} {collection}. "
        "The complete collection is available in the canonical JSON report."
    )
