from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

CHART_ROOT = Path(__file__).resolve().parents[2] / "infra" / "helm" / "medusa"


def _render_chart(extra_args: list[str] | None = None) -> str:
    """Render the Helm chart with `helm template` and return the manifest."""
    if shutil.which("helm") is None:
        pytest.skip("helm binary is required to render the Helm chart")

    cmd = ["helm", "template", "medusa", str(CHART_ROOT)]
    if extra_args:
        cmd.extend(extra_args)

    rendered = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return rendered.stdout


def _load_chart_values():
    yaml = _load_yaml()
    with (CHART_ROOT / "values.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _load_yaml():
    """Import PyYAML lazily so tests skip cleanly when the dependency is absent."""
    return pytest.importorskip("yaml")


def test_data_plane_network_policy_allows_enabled_workers():
    manifest = _render_chart()
    values = _load_chart_values()

    allowed_components = set(
        (values.get("networkPolicies", {}).get("workers", {}) or {}).get("allowedComponents", [])
    )

    expected_worker_components: set[str] = set(allowed_components)
    for worker in (values.get("workers") or {}).values():
        if not isinstance(worker, dict):
            continue
        if not worker.get("enabled"):
            continue
        component = worker.get("component")
        if not component:
            continue
        if component in allowed_components:
            expected_worker_components.add(component)

    chart_metadata = yaml.safe_load((CHART_ROOT / "Chart.yaml").read_text(encoding="utf-8"))
    expected_policy_name = f"medusa-{chart_metadata['name']}-data-plane"

    network_policy = None
    for document in yaml.safe_load_all(manifest):
        if not isinstance(document, dict):
            continue
        if document.get("kind") != "NetworkPolicy":
            continue
        if document.get("metadata", {}).get("name") == expected_policy_name:
            network_policy = document
            break

    assert network_policy is not None, "data-plane NetworkPolicy was not rendered"

    actual_components: set[str] = set()
    for rule in network_policy.get("spec", {}).get("ingress", []) or []:
        for source in rule.get("from", []) or []:
            labels = (source.get("podSelector") or {}).get("matchLabels", {})
            component = labels.get("app.kubernetes.io/component")
            if component:
                actual_components.add(component)

    # Controller access stays mandatory, and every enabled worker component must be whitelisted.
    assert "controller" in actual_components
    assert expected_worker_components.issubset(actual_components)


def _kubeconform_args() -> list[str]:
    values = _load_chart_values()
    kubeconform_cfg = (values.get("kubeconform") or {})
    args: list[str] = []
    if kubeconform_cfg.get("strict"):
        args.append("-strict")
    args.extend(kubeconform_cfg.get("additionalArgs") or [])
    return args


def test_chart_manifests_pass_kubeconform():
    kubeconform_bin = shutil.which("kubeconform")
    if kubeconform_bin is None:
        pytest.skip("kubeconform binary is required to validate the Helm chart")

    manifest = _render_chart()
    cmd = [kubeconform_bin, *_kubeconform_args(), "-"]
    subprocess.run(cmd, check=True, input=manifest, text=True)
