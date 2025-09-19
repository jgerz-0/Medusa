"""Regression coverage for nuclei profile resolution."""

from __future__ import annotations

from typing import List

import pytest

from controller.main import (
    DEFAULT_NUCLEI_TEMPLATE_PROFILE,
    NUCLEI_TEMPLATE_PROFILES,
    resolve_nuclei_job_configuration,
)


@pytest.mark.parametrize(
    "profile",
    [
        "web-baseline",
        "api-deep-dive",
        "external-attack-surface",
    ],
)
def test_resolve_nuclei_job_configuration_profiles(profile: str) -> None:
    """Ensure each preset returns its curated template list and metadata."""

    (  # Target scope unused in this test because no hosts are requested.
        resolved_profile,
        templates,
        tags,
        sanitized,
        metadata,
    ) = resolve_nuclei_job_configuration("*.medusa.local", {"profile": profile})

    assert resolved_profile == profile
    assert templates == list(NUCLEI_TEMPLATE_PROFILES[profile])
    assert tags == [f"profile:{profile}"]
    assert sanitized == {"profile": profile}
    assert metadata == {}


def test_resolve_nuclei_job_configuration_defaults_to_web_baseline() -> None:
    """Invalid profiles should sanitize to the hardened default preset."""

    (
        resolved_profile,
        templates,
        tags,
        sanitized,
        metadata,
    ) = resolve_nuclei_job_configuration("*.medusa.local", {"profile": "unknown"})

    assert resolved_profile == DEFAULT_NUCLEI_TEMPLATE_PROFILE
    expected_templates: List[str] = list(
        NUCLEI_TEMPLATE_PROFILES[DEFAULT_NUCLEI_TEMPLATE_PROFILE]
    )
    assert templates == expected_templates
    assert tags == [f"profile:{DEFAULT_NUCLEI_TEMPLATE_PROFILE}"]
    assert sanitized == {"profile": DEFAULT_NUCLEI_TEMPLATE_PROFILE}
    assert metadata == {}
