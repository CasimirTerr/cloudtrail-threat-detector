"""
Detection rules for CloudTrail events.

Each rule takes one CloudTrail record (the `detail` of an EventBridge event)
and returns an Alert, or None if the event isn't suspicious.
Add a rule by writing a function and decorating it with @rule.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis"}

RULES = []


@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    description: str
    mitre: str                       # MITRE ATT&CK technique id
    event_name: str = ""
    actor: str = ""
    source_ip: str = ""
    region: str = ""
    event_time: str = ""
    account: str = ""
    extra: dict = field(default_factory=dict)


def rule(fn):
    RULES.append(fn)
    return fn


# ------------------------------------------------------------------ helpers

def actor_of(e: dict) -> str:
    ui = e.get("userIdentity", {}) or {}
    t = ui.get("type", "")
    if t == "Root":
        return "root"
    if t == "IAMUser":
        return f"user/{ui.get('userName', '?')}"
    if t == "AssumedRole":
        arn = ui.get("arn", "")
        return arn.split(":assumed-role/")[-1] if ":assumed-role/" in arn else arn
    return ui.get("arn") or ui.get("principalId") or t or "unknown"


def _req(e):
    return e.get("requestParameters") or {}


def _make(e, rule_id, severity, title, description, mitre, **extra) -> Alert:
    return Alert(rule_id=rule_id, severity=severity, title=title, description=description, mitre=mitre,
                 event_name=e.get("eventName", ""), actor=actor_of(e),
                 source_ip=e.get("sourceIPAddress", ""), region=e.get("awsRegion", ""),
                 event_time=e.get("eventTime", ""), account=e.get("recipientAccountId", ""),
                 extra=extra)


def _failed(e) -> bool:
    return bool(e.get("errorCode"))


# ------------------------------------------------------------------ rules

@rule
def root_account_usage(e):
    ui = e.get("userIdentity", {}) or {}
    if ui.get("type") != "Root" or ui.get("invokedBy") or e.get("eventType") == "AwsServiceEvent":
        return None
    if e.get("eventName") == "ConsoleLogin" and _failed_login(e):
        return None  # handled by failed_console_login
    return _make(e, "ROOT_USAGE", "HIGH", "Root account used",
                 f"The root user called {e.get('eventName')}. Root should almost never be used day to day.",
                 "T1078.004")


def _failed_login(e) -> bool:
    return (e.get("responseElements") or {}).get("ConsoleLogin") == "Failure"


@rule
def console_login_without_mfa(e):
    if e.get("eventName") != "ConsoleLogin" or _failed_login(e):
        return None
    extra = e.get("additionalEventData") or {}
    if extra.get("MFAUsed") == "No":
        # SSO / federated logins report MFAUsed=No even when the IdP enforced MFA
        if (e.get("userIdentity") or {}).get("type") in ("AssumedRole", "FederatedUser"):
            return None
        return _make(e, "LOGIN_NO_MFA", "HIGH", "Console login without MFA",
                     "Successful console sign-in with no MFA. Stolen passwords alone are enough to get in.",
                     "T1078.004")
    return None


@rule
def failed_console_login(e):
    if e.get("eventName") == "ConsoleLogin" and _failed_login(e):
        return _make(e, "LOGIN_FAILED", "MEDIUM", "Failed console login",
                     "A console sign-in failed. Repeated failures can mean password guessing.",
                     "T1110")
    return None


@rule
def cloudtrail_tampering(e):
    name = e.get("eventName")
    if e.get("eventSource") != "cloudtrail.amazonaws.com" or _failed(e):
        return None
    if name in ("StopLogging", "DeleteTrail"):
        return _make(e, "CLOUDTRAIL_TAMPER", "CRITICAL", f"CloudTrail {('stopped' if name == 'StopLogging' else 'deleted')}",
                     "Audit logging was turned off. Attackers do this first to hide what they do next.",
                     "T1562.008", trail=_req(e).get("name", ""))
    if name in ("UpdateTrail", "PutEventSelectors"):
        return _make(e, "CLOUDTRAIL_MODIFIED", "MEDIUM", "CloudTrail configuration changed",
                     "A trail's settings or event selectors were changed. Confirm logging coverage wasn't reduced.",
                     "T1562.008", trail=_req(e).get("name", "") or _req(e).get("trailName", ""))
    return None


@rule
def guardduty_disabled(e):
    if e.get("eventSource") != "guardduty.amazonaws.com" or _failed(e):
        return None
    name = e.get("eventName")
    if name == "DeleteDetector" or (name == "UpdateDetector" and _req(e).get("enable") is False):
        return _make(e, "GUARDDUTY_DISABLED", "CRITICAL", "GuardDuty disabled",
                     "Threat detection was turned off in this region.", "T1562.001")
    return None


@rule
def iam_persistence(e):
    if e.get("eventSource") != "iam.amazonaws.com" or _failed(e):
        return None
    name, req = e.get("eventName"), _req(e)
    if name == "CreateUser":
        return _make(e, "IAM_USER_CREATED", "MEDIUM", "New IAM user created",
                     f"User '{req.get('userName')}' was created. Attackers create users to keep access.",
                     "T1136.003", new_user=req.get("userName", ""))
    if name == "CreateAccessKey":
        target = req.get("userName") or actor_of(e)
        return _make(e, "ACCESS_KEY_CREATED", "MEDIUM", "New access key created",
                     f"A long-lived access key was created for {target}.", "T1098.001", target_user=target)
    if name in ("CreateLoginProfile", "UpdateLoginProfile"):
        return _make(e, "LOGIN_PROFILE_CHANGED", "MEDIUM", "Console password set or changed",
                     f"Console password was set for '{req.get('userName')}'. Unexpected changes can mean account takeover.",
                     "T1098", target_user=req.get("userName", ""))
    return None


@rule
def admin_privilege_granted(e):
    if e.get("eventSource") != "iam.amazonaws.com" or _failed(e):
        return None
    name, req = e.get("eventName"), _req(e)
    target = req.get("userName") or req.get("roleName") or req.get("groupName") or ""
    if name in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
        arn = req.get("policyArn", "")
        if arn.endswith(":policy/AdministratorAccess") or arn.endswith(":policy/IAMFullAccess"):
            return _make(e, "ADMIN_GRANTED", "HIGH", "Admin policy attached",
                         f"{arn.rsplit('/', 1)[-1]} was attached to {target}.", "T1098", target=target, policy=arn)
    if name in ("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"):
        doc = req.get("policyDocument", "{}")
        try:
            doc = json.loads(doc) if isinstance(doc, str) else doc
        except ValueError:
            return None
        stmts = doc.get("Statement", [])
        stmts = stmts if isinstance(stmts, list) else [stmts]
        for s in stmts:
            acts = s.get("Action", [])
            res = s.get("Resource", [])
            acts = acts if isinstance(acts, list) else [acts]
            res = res if isinstance(res, list) else [res]
            if s.get("Effect") == "Allow" and "*" in acts and "*" in res:
                return _make(e, "ADMIN_GRANTED", "HIGH", "Inline admin policy added",
                             f"Inline policy '{req.get('policyName')}' on {target} allows every action on every resource.",
                             "T1098", target=target)
    return None


@rule
def security_group_opened(e):
    if e.get("eventName") != "AuthorizeSecurityGroupIngress" or _failed(e):
        return None
    req = _req(e)
    perms = (req.get("ipPermissions") or {}).get("items", [])
    for p in perms:
        cidrs = [r.get("cidrIp") for r in (p.get("ipRanges") or {}).get("items", [])]
        cidrs += [r.get("cidrIpv6") for r in (p.get("ipv6Ranges") or {}).get("items", [])]
        open_cidrs = sorted(OPEN_CIDRS.intersection(cidrs))
        if not open_cidrs:
            continue
        lo, hi = p.get("fromPort"), p.get("toPort")
        proto = p.get("ipProtocol")
        if proto == "-1" or lo is None:
            exposed = "all ports"
            sev = "CRITICAL"
        else:
            hits = [f"{ADMIN_PORTS[port]} ({port})" for port in ADMIN_PORTS if lo <= port <= hi]
            exposed = ", ".join(hits) if hits else (f"port {lo}" if lo == hi else f"ports {lo}-{hi}")
            sev = "HIGH" if hits else "MEDIUM"
        return _make(e, "SG_OPEN_TO_WORLD", sev, "Security group opened to the internet",
                     f"Security group {req.get('groupId', '?')} now allows {exposed} from anywhere ({', '.join(open_cidrs)}).",
                     "T1562.007", group_id=req.get("groupId", ""))
    return None


@rule
def s3_made_public(e):
    if e.get("eventSource") != "s3.amazonaws.com" or _failed(e):
        return None
    name, req = e.get("eventName"), _req(e)
    bucket = req.get("bucketName", "?")
    if name == "DeleteBucketPublicAccessBlock":
        return _make(e, "S3_BPA_REMOVED", "HIGH", "S3 Block Public Access removed",
                     f"Block Public Access was deleted on bucket '{bucket}'.", "T1530", bucket=bucket)
    if name == "PutBucketPublicAccessBlock":
        cfg = req.get("PublicAccessBlockConfiguration") or {}
        keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        off = [k for k in keys if cfg.get(k) is False]
        if off:
            return _make(e, "S3_BPA_WEAKENED", "HIGH", "S3 Block Public Access weakened",
                         f"On bucket '{bucket}' these were turned off: {', '.join(off)}.", "T1530", bucket=bucket)
    if name == "PutBucketPolicy":
        pol = req.get("bucketPolicy") or {}
        if isinstance(pol, str):
            try:
                pol = json.loads(pol)
            except ValueError:
                pol = {}
        stmts = pol.get("Statement", [])
        stmts = stmts if isinstance(stmts, list) else [stmts]
        for s in stmts:
            p = s.get("Principal")
            if s.get("Effect") == "Allow" and (p == "*" or (isinstance(p, dict) and p.get("AWS") == "*")) \
                    and not s.get("Condition"):
                return _make(e, "S3_PUBLIC_POLICY", "HIGH", "S3 bucket policy made public",
                             f"Bucket '{bucket}' now has a policy allowing anyone (Principal \"*\").", "T1530",
                             bucket=bucket)
    if name == "PutBucketAcl":
        blob = json.dumps(req)
        if "AllUsers" in blob or "AuthenticatedUsers" in blob or req.get("x-amz-acl") in (["public-read"], "public-read",
                                                                                            ["public-read-write"],
                                                                                            "public-read-write"):
            return _make(e, "S3_PUBLIC_ACL", "HIGH", "S3 bucket ACL made public",
                         f"Bucket '{bucket}' ACL now grants access to everyone.", "T1530", bucket=bucket)
    return None


@rule
def kms_key_destruction(e):
    if e.get("eventSource") != "kms.amazonaws.com" or _failed(e):
        return None
    name = e.get("eventName")
    if name in ("ScheduleKeyDeletion", "DisableKey"):
        key = _req(e).get("keyId", "?")
        return _make(e, "KMS_KEY_DESTRUCTION", "HIGH",
                     "KMS key scheduled for deletion" if name == "ScheduleKeyDeletion" else "KMS key disabled",
                     f"KMS key {key} was {('scheduled for deletion' if name == 'ScheduleKeyDeletion' else 'disabled')}. "
                     "Data encrypted with it may become unreadable (ransomware pattern).",
                     "T1485", key_id=key)
    return None


def evaluate(event: dict) -> list[Alert]:
    """Run every rule against one CloudTrail record."""
    alerts = [a for a in (r(event) for r in RULES) if a]
    alerts.sort(key=lambda a: SEVERITY_ORDER[a.severity])
    return alerts
