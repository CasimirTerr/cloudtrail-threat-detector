import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detector.rules import evaluate  # noqa: E402

EVENTS = Path(__file__).parent / "events"


def load(kind, name):
    return json.loads((EVENTS / kind / f"{name}.json").read_text())


# every malicious sample -> the rule (and severity) we expect to fire
EXPECTED = {
    "root_console_login": ("ROOT_USAGE", "HIGH"),
    "login_no_mfa": ("LOGIN_NO_MFA", "HIGH"),
    "login_failed": ("LOGIN_FAILED", "MEDIUM"),
    "stop_logging": ("CLOUDTRAIL_TAMPER", "CRITICAL"),
    "delete_trail": ("CLOUDTRAIL_TAMPER", "CRITICAL"),
    "guardduty_delete": ("GUARDDUTY_DISABLED", "CRITICAL"),
    "create_user": ("IAM_USER_CREATED", "MEDIUM"),
    "create_access_key": ("ACCESS_KEY_CREATED", "MEDIUM"),
    "attach_admin": ("ADMIN_GRANTED", "HIGH"),
    "inline_admin": ("ADMIN_GRANTED", "HIGH"),
    "sg_open_ssh": ("SG_OPEN_TO_WORLD", "HIGH"),
    "sg_open_all": ("SG_OPEN_TO_WORLD", "CRITICAL"),
    "s3_bpa_deleted": ("S3_BPA_REMOVED", "HIGH"),
    "s3_public_policy": ("S3_PUBLIC_POLICY", "HIGH"),
    "s3_public_acl": ("S3_PUBLIC_ACL", "HIGH"),
    "kms_schedule_delete": ("KMS_KEY_DESTRUCTION", "HIGH"),
}


@pytest.mark.parametrize("name,expected", EXPECTED.items())
def test_malicious_event_fires_expected_rule(name, expected):
    alerts = evaluate(load("malicious", name))
    assert alerts, f"{name}: no alert fired"
    assert (alerts[0].rule_id, alerts[0].severity) == expected


def test_every_malicious_sample_is_covered():
    files = {p.stem for p in (EVENTS / "malicious").glob("*.json")}
    assert files == set(EXPECTED), "add new sample events to EXPECTED"


@pytest.mark.parametrize("path", sorted((EVENTS / "benign").glob("*.json")), ids=lambda p: p.stem)
def test_benign_events_do_not_alert(path):
    assert evaluate(json.loads(path.read_text())) == []


def test_alert_carries_context():
    a = evaluate(load("malicious", "sg_open_ssh"))[0]
    assert a.actor == "user/jsmith"
    assert a.source_ip == "203.0.113.45"
    assert a.extra["group_id"] == "sg-0a1b2c3d4e5f67890"
    assert "SSH (22)" in a.description
    assert a.mitre.startswith("T")
