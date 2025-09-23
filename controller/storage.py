"""Object storage helpers for report export artifacts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

try:  # pragma: no cover - optional dependency during type checking
    import boto3
    from botocore.client import Config as BotoConfig
    from botocore.exceptions import BotoCoreError, ClientError
except ModuleNotFoundError:  # pragma: no cover
    boto3 = None  # type: ignore[assignment]
    BotoConfig = None  # type: ignore[assignment]
    BotoCoreError = Exception  # type: ignore[misc,assignment]
    ClientError = Exception  # type: ignore[misc,assignment]


class ReportStorageError(RuntimeError):
    """Raised when persisting or retrieving report artifacts fails."""


@dataclass
class ReportStorageReference:
    """Location of a stored report artifact in object storage."""

    bucket: str
    key: str
    content_type: str


class ReportStorage(Protocol):
    """Protocol implemented by report artifact storage backends."""

    def store(
        self,
        *,
        report_id: str,
        data: bytes,
        content_type: str,
        extension: str,
    ) -> ReportStorageReference:
        """Persist the artifact and return its storage reference."""

    def fetch(self, reference: ReportStorageReference) -> bytes:
        """Retrieve the artifact represented by ``reference``."""


class S3ReportStorage:
    """Persist report exports using an S3-compatible backend (MinIO)."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        region_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
        force_path_style: bool = True,
    ) -> None:
        if boto3 is None:  # pragma: no cover - runtime guard
            raise ReportStorageError("boto3 must be installed to use S3ReportStorage")

        self._bucket = bucket
        normalized_prefix = (prefix or "").strip("/")
        self._prefix = normalized_prefix

        session = boto3.session.Session()
        client_config = None
        if force_path_style and BotoConfig is not None:
            client_config = BotoConfig(s3={"addressing_style": "path"})
        self._client = session.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region_name,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            config=client_config,
        )

    def _build_key(self, report_id: str, extension: str) -> str:
        key = f"{report_id}.{extension}"
        if self._prefix:
            return f"{self._prefix}/{key}"
        return key

    def store(
        self,
        *,
        report_id: str,
        data: bytes,
        content_type: str,
        extension: str,
    ) -> ReportStorageReference:
        key = self._build_key(report_id, extension)
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=data,
                ContentType=content_type,
            )
        except (BotoCoreError, ClientError) as exc:  # pragma: no cover - network call
            raise ReportStorageError("Failed to persist report export to S3") from exc
        return ReportStorageReference(
            bucket=self._bucket,
            key=key,
            content_type=content_type,
        )

    def fetch(self, reference: ReportStorageReference) -> bytes:
        try:
            response = self._client.get_object(
                Bucket=reference.bucket,
                Key=reference.key,
            )
        except (BotoCoreError, ClientError) as exc:  # pragma: no cover - network call
            raise ReportStorageError("Failed to retrieve report export from S3") from exc
        body = response.get("Body")
        if body is None:
            raise ReportStorageError("S3 response missing body payload")
        data = body.read()
        if not isinstance(data, (bytes, bytearray)):
            raise ReportStorageError("Invalid payload returned from S3")
        return bytes(data)


class EphemeralReportStorage:
    """In-memory fallback storage used when S3 credentials are not available."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def store(
        self,
        *,
        report_id: str,
        data: bytes,
        content_type: str,
        extension: str,
    ) -> ReportStorageReference:
        key = f"{report_id}.{extension}"
        self._objects[key] = bytes(data)
        return ReportStorageReference(
            bucket="ephemeral-reports",
            key=key,
            content_type=content_type,
        )

    def fetch(self, reference: ReportStorageReference) -> bytes:
        try:
            return self._objects[reference.key]
        except KeyError as exc:  # pragma: no cover - runtime guard
            raise ReportStorageError("Report artifact not found in ephemeral storage") from exc
