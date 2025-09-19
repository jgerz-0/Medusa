from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from controller.db.models import Base, BinarySample
from workers.binary.preprocess.inspection import FileDescriptor
from workers.binary.preprocess.schemas import BinaryPreprocessJob
from workers.binary.preprocess.storage import MetadataRepository
from workers.binary.preprocess.worker import BinaryPreprocessWorker, WorkerConfig


class FakeStorage:
    def __init__(self, objects: dict[tuple[str, str], bytes]) -> None:
        self._objects = dict(objects)
        self.saved_json: dict[tuple[str, str], dict] = {}

    def fetch(self, bucket: str, key: str) -> bytes:
        return self._objects[(bucket, key)]

    def put_json(self, bucket: str, key: str, payload: dict) -> None:
        self.saved_json[(bucket, key)] = payload


class StubInspector:
    def __init__(self, descriptor: FileDescriptor) -> None:
        self._descriptor = descriptor

    def identify(self, payload: bytes) -> FileDescriptor:
        return self._descriptor


@pytest.fixture()
def session_factory() -> sessionmaker:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return factory


def _descriptor_for(data: bytes, mime: str) -> FileDescriptor:
    return FileDescriptor(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        mime_type=mime,
        magic_label=f"detected/{mime}",
    )


def _make_job(**overrides) -> BinaryPreprocessJob:
    payload = {
        "job_id": "job-123",
        "scan_id": "scan-abc",
        "target_id": "target-1",
        "target_scope": "scope.example",
        "object_bucket": "uploads",
        "object_key": "sample.bin",
        "file_name": "sample.bin",
        "submitted_by": "analyst@example",
        "submitted_at": datetime.now(tz=timezone.utc),
        "metadata": {"source": "unit-test"},
    }
    payload.update(overrides)
    return BinaryPreprocessJob.model_validate(payload)


def test_process_job_persists_metadata_and_uploads_json(session_factory: sessionmaker) -> None:
    sample_bytes = b"MZ" + b"\x00" * 10
    descriptor = _descriptor_for(sample_bytes, "application/x-dosexec")
    storage = FakeStorage({("uploads", "sample.bin"): sample_bytes})
    inspector = StubInspector(descriptor)

    repo = MetadataRepository(session_factory)
    config = WorkerConfig(
        allowed_mime_types=("application/x-dosexec",), metadata_bucket="metadata"
    )
    worker = BinaryPreprocessWorker(
        config,
        inspector=inspector,
        storage=storage,
        repository=repo,
        policies=None,
        session_factory=session_factory,
    )

    job = _make_job()
    result = worker.process_job(job)

    assert result.policy_status == "allowed"
    assert result.sha256 == descriptor.sha256

    with session_factory() as session:
        records = session.query(BinarySample).all()
        assert len(records) == 1
        record = records[0]
        assert record.policy_status == "allowed"
        assert record.sha256 == descriptor.sha256
        assert record.storage_bucket == "uploads"
        assert record.storage_key == "sample.bin"

    metadata_key = next(iter(storage.saved_json))
    assert metadata_key[0] == "metadata"
    payload = storage.saved_json[metadata_key]
    assert payload["policy_allowed"] is True
    assert payload["target_scope"] == "scope.example"


def test_policy_blocked_artifact(session_factory: sessionmaker) -> None:
    sample_bytes = b"%PDF" + b"\x00" * 8
    descriptor = _descriptor_for(sample_bytes, "application/pdf")
    storage = FakeStorage({("uploads", "sample.pdf"): sample_bytes})
    inspector = StubInspector(descriptor)

    repo = MetadataRepository(session_factory)
    config = WorkerConfig(allowed_mime_types=("application/x-dosexec",), metadata_bucket="uploads")
    worker = BinaryPreprocessWorker(
        config,
        inspector=inspector,
        storage=storage,
        repository=repo,
        policies=None,
        session_factory=session_factory,
    )

    job = _make_job(object_key="sample.pdf", file_name="sample.pdf")
    result = worker.process_job(job)

    assert result.policy_status == "blocked"
    assert result.policy_reasons

    with session_factory() as session:
        record = session.query(BinarySample).one()
        assert record.policy_status == "blocked"
        assert record.policy_reasons

    metadata_payload = storage.saved_json[
        ("uploads", f"preprocess/metadata/{descriptor.sha256}.json")
    ]
    assert metadata_payload["policy_allowed"] is False
    assert metadata_payload["policy_status"] == "blocked"
