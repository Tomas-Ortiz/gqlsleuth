"""Canonical JSON serialization and package-loaded Jinja2 human report renderers."""

import base64
import html
import json
import re
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from uuid import UUID

from jinja2 import Environment, PackageLoader, StrictUndefined, TemplateError
from pydantic import BaseModel, JsonValue

from gqlsleuth.domain.exceptions import ReportingError
from gqlsleuth.reporting.differential import differential_sections
from gqlsleuth.reporting.models import DifferentialReportContext, ReportContext, ReportFormat
from gqlsleuth.reporting.presentation import human_sections


def render_report(context: ReportContext | DifferentialReportContext, format: ReportFormat) -> str:
    """Render one context; bytes use explicit lossless base64 objects in canonical JSON."""
    if not isinstance(format, ReportFormat):
        raise ReportingError("Unsupported report format.")
    try:
        if format is ReportFormat.JSON:
            return (
                json.dumps(
                    _json_value(context),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                    allow_nan=False,
                )
                + "\n"
            )
        if format not in {ReportFormat.MARKDOWN, ReportFormat.HTML}:
            raise ReportingError("Unsupported report format.")
        environment = Environment(
            loader=PackageLoader("gqlsleuth.reporting", "templates"),
            autoescape=format is ReportFormat.HTML,
            undefined=StrictUndefined,
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters.update(brief=_brief, markdown_text=_markdown_text, fenced=_fenced)
        name = "report.html.j2" if format is ReportFormat.HTML else "report.md.j2"
        sections = (
            differential_sections(context)
            if isinstance(context, DifferentialReportContext)
            else human_sections(context)
        )
        return environment.get_template(name).render(sections=sections)
    except (TemplateError, OSError, TypeError, ValueError, RecursionError) as error:
        raise ReportingError(
            f"Could not render {format} report: {type(error).__name__}."
        ) from error


def _json_value(value: object) -> JsonValue:
    if isinstance(value, Enum):
        return _json_value(value.value)
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, BaseModel):
        # Serialize declared fields directly to retain subclass evidence fields and raw bytes.
        return {name: _json_value(getattr(value, name)) for name in type(value).model_fields}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in fields(value)
            if not (
                isinstance(value, (ReportContext, DifferentialReportContext))
                and field.name
                in {
                    "ai_interpretation",
                    "multiplicity",
                    "query_depth",
                    "sequential_object_discovery",
                    "nested_authorization_review",
                    "object_authorization_review",
                    "authorization_policy_validation",
                    "object_lookup_follow_up",
                    "mutation_authorization",
                    "sensitive_input_review",
                    "sensitive_input_validation",
                    "idor_bola_detection",
                    "authentication_token_security",
                }
                and getattr(value, field.name) is None
            )
        }
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings.")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    raise TypeError(f"Unsupported report value: {type(value).__name__}.")


def _brief(value: str) -> str:
    return value if len(value) <= 600 else value[:600] + "… (see JSON for full text)"


def _markdown_text(value: str) -> str:
    # Text is not Markdown authored by the target. Escape formatting and inline HTML.
    text = html.escape(_brief(value), quote=False).replace("\n", " ").replace("\r", " ")
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)


def _fenced(value: str, language: str) -> str:
    fence = "`" * max(3, 1 + max((len(item) for item in re.findall(r"`+", value)), default=0))
    return f"{fence}{language}\n{value}\n{fence}"
