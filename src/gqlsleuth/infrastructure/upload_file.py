"""Bounded local file reads and fixed benign variants; paths/bytes stay runtime-only."""

import hashlib
import mimetypes
import os
import re
import stat
from pathlib import Path

from gqlsleuth.domain.exceptions import HttpConfigurationError
from gqlsleuth.domain.file_upload import MAX_PHASE28_FILE_BYTES, UploadFileMetadata, UploadProbe

BENIGN_UPLOAD_CONTENT = b"GQLSleuth benign file-upload validation payload.\n"
_MIME = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+")


def validate_upload_mime(value: str | None) -> None:
    if value is not None and not _MIME.fullmatch(value):
        raise HttpConfigurationError("Upload content type must be a plain MIME type/subtype.")


def read_upload_file(
    path: Path, content_type: str | None = None
) -> tuple[UploadFileMetadata, bytes]:
    validate_upload_mime(content_type)
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError
        with path.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError
            data = stream.read(MAX_PHASE28_FILE_BYTES + 1)
    except (OSError, ValueError):
        raise HttpConfigurationError(
            "Upload file must be an existing readable regular file."
        ) from None
    if not 0 < len(data) <= MAX_PHASE28_FILE_BYTES:
        raise HttpConfigurationError("Upload file must contain 1 byte to 1 MiB.")
    filename = path.name
    if any(ord(c) < 32 or c in "/\\:%" or ord(c) == 127 for c in filename) or filename in {
        "",
        ".",
        "..",
    }:
        raise HttpConfigurationError(
            "Upload basename must not contain paths or encoded separators."
        )
    # Avoid platform registry/user MIME files so filename inference is reproducible.
    mime = (
        content_type
        or mimetypes.MimeTypes(filenames=()).guess_type(filename)[0]
        or "application/octet-stream"
    )
    return metadata(filename, mime, data), data


def metadata(filename: str, mime: str, data: bytes) -> UploadFileMetadata:
    return UploadFileMetadata(filename, len(data), hashlib.sha256(data).hexdigest(), mime)


def upload_variant(
    baseline: UploadFileMetadata, data: bytes, probe: UploadProbe
) -> tuple[UploadFileMetadata, bytes]:
    filename, mime = baseline.filename, baseline.content_type
    if probe is UploadProbe.CONTENT_MISMATCH:
        data = BENIGN_UPLOAD_CONTENT
    elif probe is UploadProbe.MIME_MISMATCH:
        mime = "text/plain" if mime.lower() != "text/plain" else "application/octet-stream"
    elif probe is UploadProbe.EXTENSION_MISMATCH:
        # Remove other dots as well: the alternate must not contain double extensions.
        stem = Path(filename).stem.replace(".", "_") or "upload"
        filename = stem + (".bin" if Path(filename).suffix.lower() == ".txt" else ".txt")
    return metadata(filename, mime, data), data
