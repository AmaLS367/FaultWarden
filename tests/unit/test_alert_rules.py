"""Unit tests for Prometheus alerting rules and configuration syntax."""

from pathlib import Path

import yaml


# --- Prometheus & Alertmanager Config Validation Tests ---
def test_prometheus_alert_rules_syntax() -> None:
    """Ensure alert_rules.yml is well-formed YAML and contains valid Prometheus rule structures."""

    rule_file = Path(__file__).parents[2] / "observability" / "prometheus" / "alert_rules.yml"
    assert rule_file.exists(), f"Rule file not found at {rule_file}"

    with rule_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "groups" in data
    assert isinstance(data["groups"], list)
    assert len(data["groups"]) >= 1

    demo_group = next((g for g in data["groups"] if g.get("name") == "demo_service_alerts"), None)
    assert demo_group is not None, "demo_service_alerts group missing"
    assert "rules" in demo_group
    assert len(demo_group["rules"]) >= 1

    high_5xx_rule = next(
        (
            r
            for r in demo_group["rules"]
            if r.get("alert") in ("DemoServiceHighErrorRate", "High5xxRate")
        ),
        None,
    )
    assert high_5xx_rule is not None, "5xx error rate alert rule missing"
    assert "expr" in high_5xx_rule
    assert "http_requests_total" in high_5xx_rule["expr"]
    assert "labels" in high_5xx_rule
    assert high_5xx_rule["labels"].get("severity") in ("critical", "high", "warning")
    assert high_5xx_rule["labels"].get("service") == "demo-service"
    assert "annotations" in high_5xx_rule
    assert "summary" in high_5xx_rule["annotations"]


def test_prometheus_config_syntax() -> None:
    """Ensure prometheus.yml is well-formed and declares demo-service and alertmanager."""
    config_file = Path(__file__).parents[2] / "observability" / "prometheus" / "prometheus.yml"
    assert config_file.exists(), f"Config file not found at {config_file}"

    with config_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "scrape_configs" in data
    job_names = [sc["job_name"] for sc in data["scrape_configs"]]
    assert "demo-service" in job_names
    assert "faultwarden" in job_names


def test_alertmanager_config_syntax() -> None:
    """Ensure alertmanager.yml is well-formed and declares webhook receiver."""
    config_file = Path(__file__).parents[2] / "observability" / "alertmanager" / "alertmanager.yml"
    assert config_file.exists(), f"Config file not found at {config_file}"

    with config_file.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "route" in data
    assert "receivers" in data
    receiver_names = [r["name"] for r in data["receivers"]]
    assert "faultwarden_webhook" in receiver_names

    webhook_configs = data["receivers"][0].get("webhook_configs", [])
    assert len(webhook_configs) >= 1
    assert "faultwarden:8000/api/v1/alerts/alertmanager" in webhook_configs[0]["url"]
    assert webhook_configs[0].get("send_resolved") is True
