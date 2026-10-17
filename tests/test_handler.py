import json
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detector import handler  # noqa: E402

EVENTS = Path(__file__).parent / "events"


def eventbridge(name, kind="malicious"):
    detail = json.loads((EVENTS / kind / f"{name}.json").read_text())
    return {"version": "0", "detail-type": "AWS API Call via CloudTrail", "source": "aws." + detail["eventSource"].split(".")[0],
            "account": "123456789012", "region": "us-east-1", "detail": detail}


@pytest.fixture
def sns_setup(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        sns = boto3.client("sns", region_name="us-east-1")
        sqs = boto3.client("sqs", region_name="us-east-1")
        topic = sns.create_topic(Name="alerts")["TopicArn"]
        q = sqs.create_queue(QueueName="inbox")["QueueUrl"]
        q_arn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn)
        monkeypatch.setenv("SNS_TOPIC_ARN", topic)
        handler._sns = None
        yield sqs, q
        handler._sns = None


def received(sqs, q):
    msgs = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10).get("Messages", [])
    return [json.loads(m["Body"]) for m in msgs]


def test_alert_published_to_sns(sns_setup):
    sqs, q = sns_setup
    out = handler.lambda_handler(eventbridge("stop_logging"))
    assert out == {"alerts": 1, "rules": ["CLOUDTRAIL_TAMPER"]}
    msgs = received(sqs, q)
    assert len(msgs) == 1
    assert msgs[0]["Subject"].startswith("[CRITICAL] CloudTrail stopped")
    assert "user/deploy-bot" in msgs[0]["Message"]


def test_benign_event_sends_nothing(sns_setup):
    sqs, q = sns_setup
    assert handler.lambda_handler(eventbridge("describe_instances", "benign"))["alerts"] == 0
    assert received(sqs, q) == []


def test_min_severity_filter(sns_setup, monkeypatch):
    monkeypatch.setenv("MIN_SEVERITY", "HIGH")
    assert handler.lambda_handler(eventbridge("create_user"))["alerts"] == 0      # MEDIUM -> filtered
    assert handler.lambda_handler(eventbridge("attach_admin"))["alerts"] == 1     # HIGH -> sent


def test_ignore_actors(sns_setup, monkeypatch):
    monkeypatch.setenv("IGNORE_ACTORS", "user/deploy-bot")
    assert handler.lambda_handler(eventbridge("stop_logging"))["alerts"] == 0


def test_works_without_topic(monkeypatch):
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
    assert handler.lambda_handler(eventbridge("sg_open_all"))["alerts"] == 1
