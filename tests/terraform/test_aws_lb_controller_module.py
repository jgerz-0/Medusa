from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LB_MODULE = REPO_ROOT / "infra" / "terraform" / "modules" / "aws_lb_controller"
TF_ENVS = REPO_ROOT / "infra" / "terraform" / "envs"


def test_module_emits_shield_and_waf_annotations() -> None:
    module_body = (LB_MODULE / "main.tf").read_text(encoding="utf-8")

    assert "alb.ingress.kubernetes.io/shield-advanced-protection" in module_body
    assert "alb.ingress.kubernetes.io/waf-acl-arn" in module_body


def test_environment_tfvars_enable_alb_hardening() -> None:
    for env in ("dev", "prod"):
        tfvars = (TF_ENVS / env / "terraform.tfvars").read_text(encoding="utf-8")
        assert "aws_lb_controller_enable_shield_advanced" in tfvars
        assert "aws_lb_controller_waf_web_acl_arn" in tfvars
        assert "aws_lb_controller_ssl_policy" in tfvars
