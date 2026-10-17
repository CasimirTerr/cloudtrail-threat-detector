"""
AWS Lambda entry point.

Triggered by an EventBridge rule that matches CloudTrail events. Runs every
detection rule and publishes an alert to SNS for anything at or above
MIN_SEVERITY.

Environment variables:
  SNS_TOPIC_ARN   topic to publish alerts to (required to send)
  MIN_SEVERITY    CRITICAL | HIGH | MEDIUM | LOW   (default MEDIUM)
  IGNORE_ACTORS   comma-separated actors to skip, e.g. "user/terraform-ci"
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict

try:                                    # package import (tests, local scripts)
    from detector.rules import SEVERITY_ORDER, Alert, evaluate
except ImportError:                     # flat import (inside the Lambda zip)
    from rules import SEVERITY_ORDER, Alert, evaluate

log = logging.getLogger()
log.setLevel(logging.INFO)

_sns = None


def _sns_client():
    global _sns
    if _sns is None:
        import boto3
        _sns = boto3.client("sns")
    return _sns


def format_alert(a: Alert) -> tuple[str, str]:
    subject = f"[{a.severity}] {a.title}"[:100]          # SNS subject limit
    lines = [
        f"{a.severity}: {a.title}",
        "",
        a.description,
        "",
        f"Who:        {a.actor}",
        f"Action:     {a.event_name}",
        f"Source IP:  {a.source_ip or '-'}",
        f"Region:     {a.region}",
        f"Account:    {a.account}",
        f"Time:       {a.event_time}",
        f"MITRE:      {a.mitre}  https://attack.mitre.org/techniques/{a.mitre.replace('.', '/')}/",
    ]
    for k, v in a.extra.items():
        if v:
            lines.append(f"{k}: {v}")
    lines += ["", "Rule: " + a.rule_id]
    return subject, "\n".join(lines)


def lambda_handler(event, context=None):
    record = event.get("detail", event)          # EventBridge wraps the CloudTrail record in "detail"
    min_sev = SEVERITY_ORDER.get(os.environ.get("MIN_SEVERITY", "MEDIUM").upper(), 2)
    ignore = {x.strip() for x in os.environ.get("IGNORE_ACTORS", "").split(",") if x.strip()}
    topic = os.environ.get("SNS_TOPIC_ARN")

    alerts = [a for a in evaluate(record)
              if SEVERITY_ORDER[a.severity] <= min_sev and a.actor not in ignore]

    for a in alerts:
        subject, body = format_alert(a)
        log.info(json.dumps({"alert": asdict(a)}))      # structured log line -> CloudWatch
        if topic:
            _sns_client().publish(TopicArn=topic, Subject=subject, Message=body,
                                  MessageAttributes={"severity": {"DataType": "String",
                                                                  "StringValue": a.severity}})
    return {"alerts": len(alerts), "rules": [a.rule_id for a in alerts]}
