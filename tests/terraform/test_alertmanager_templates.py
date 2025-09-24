from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OBSERVABILITY_MODULE = REPO_ROOT / "infra" / "terraform" / "modules" / "observability"


def test_alertmanager_config_template_uses_external_secret_mounts() -> None:
    template = (OBSERVABILITY_MODULE / "templates" / "alertmanager-default.tftpl").read_text(encoding="utf-8")

    assert "routing_key_file" in template, "PagerDuty integration must source the routing key from a mounted secret file"
    assert "api_url_file" in template, "Slack integration must source the webhook from a mounted secret file"
    assert "/etc/alertmanager/secrets" in template, "Config should never inline long-lived credentials"


def test_common_template_defines_message_blocks() -> None:
    go_templates = (OBSERVABILITY_MODULE / "templates" / "medusa-common.tmpl").read_text(encoding="utf-8")

    assert "medusa.slack.title" in go_templates
    assert "medusa.slack.body" in go_templates
    assert "medusa.pagerduty.summary" in go_templates


def test_root_module_references_bundled_template() -> None:
    main_tf = (REPO_ROOT / "infra" / "terraform" / "main.tf").read_text(encoding="utf-8")

    assert "alertmanager-default.tftpl" in main_tf
