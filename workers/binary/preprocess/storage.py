"""Persistence helpers used by the binary preprocess worker."""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from controller.db.models import Base, BinarySample, Scan
from workers.binary.preprocess.schemas import NormalizedBinaryMetadata

LOG = logging.getLogger("medusa.workers.binary.preprocess.storage")

try:  # pragma: no cover - boto3 optional in unit tests
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore[assignment]

    class BotoCoreError(Exception):  # type: ignore[no-redef]
        pass

    class ClientError(Exception):  # type: ignore[no-redef]
        pass


class ObjectStorageClient:
    """Abstract client for object storage backends."""

    def fetch(self, bucket: str, key: str) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def put_json(self, bucket: str, key: str, payload: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError


class S3ObjectStorageClient(ObjectStorageClient):
    """Thin boto3 wrapper compatible with MinIO/S3 backends."""

    def __init__(
        self,
        *,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region_name: Optional[str] = None,
    ) -> None:
        if boto3 is None:
            raise RuntimeError("boto3 is required for S3 object storage access")
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name,
        )

    def fetch(self, bucket: str, key: str) -> bytes:
        response = self._client.get_object(Bucket=bucket, Key=key)
        body = response["Body"]
        return body.read()

    def put_json(self, bucket: str, key: str, payload: Dict[str, Any]) -> None:
        serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
        self._client.put_object(
            Bucket=bucket,
            Key=key,
            Body=serialized,
            ContentType="application/json",
        )


@dataclass
class RepositoryConfig:
    """Configuration for metadata persistence."""

    database_url: str

    def session_factory(self) -> Callable[[], Session]:
        engine = create_engine(self.database_url, future=True)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        return factory


class MetadataRepository:
    """Persist normalized metadata to the Postgres database."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def persist(self, metadata: NormalizedBinaryMetadata) -> BinarySample:
        with self.session_scope() as session:
            record = BinarySample(
                scan_id=metadata.scan_id,
                target_id=metadata.target_id,
                file_name=metadata.file_name,
                sha256=metadata.sha256,
                file_size=metadata.file_size,
                mime_type=metadata.mime_type,
                magic_type=metadata.magic_label,
                policy_status=metadata.policy_status,
                policy_reasons=list(metadata.policy_reasons),
                storage_bucket=metadata.storage_bucket,
                storage_key=metadata.storage_key,
                metadata_json=dict(metadata.extra_metadata),
                metadata_hash="",
                processed_at=metadata.inspected_at,
            )
            session.add(record)
            session.flush()
            session.refresh(record)

            scan = session.get(Scan, metadata.scan_id)
            if scan is not None:
                scan.status = "processed"
                if scan.started_at is None:
                    scan.started_at = metadata.inspected_at
                scan.completed_at = metadata.inspected_at
                LOG.info(
                    "Marked scan processed",
                    extra={
                        "scan_id": metadata.scan_id,
                        "status": scan.status,
                        "completed_at": metadata.inspected_at.isoformat(),
                    },
                )

            LOG.info(
                "Persisted binary metadata",
                extra={"scan_id": metadata.scan_id, "sha256": metadata.sha256},
            )
            return record


__all__ = [
    "MetadataRepository",
    "ObjectStorageClient",
    "RepositoryConfig",
    "S3ObjectStorageClient",
]
