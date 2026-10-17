"""Generates realistic sample CloudTrail records into tests/events/ (malicious/ and benign/)."""
import hashlib, json, os
ACCT = "123456789012"
BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "events")

def user(name):
    return {"type": "IAMUser", "principalId": "AIDAEXAMPLE" + name.upper()[:6], "arn": f"arn:aws:iam::{ACCT}:user/{name}",
            "accountId": ACCT, "userName": name}
ROOT = {"type": "Root", "principalId": ACCT, "arn": f"arn:aws:iam::{ACCT}:root", "accountId": ACCT}

def ev(name, source, who, req=None, resp=None, ip="203.0.113.45", region="us-east-1", **kw):
    d = {"eventVersion": "1.09", "userIdentity": who, "eventTime": "2026-10-17T21:14:03Z",
         "eventSource": source, "eventName": name, "awsRegion": region, "sourceIPAddress": ip,
         "userAgent": "aws-cli/2.17.0", "requestParameters": req, "responseElements": resp,
         "eventID": "e7c1f6a2-0000-4000-8000-" + hashlib.md5((name + source + str(req)).encode()).hexdigest()[:12],
         "eventType": "AwsApiCall", "managementEvent": True, "recipientAccountId": ACCT}
    d.update(kw); return d

malicious = {
 "root_console_login": ev("ConsoleLogin", "signin.amazonaws.com", ROOT, None, {"ConsoleLogin": "Success"},
                          additionalEventData={"MFAUsed": "Yes", "LoginTo": "https://console.aws.amazon.com/"},
                          eventType="AwsConsoleSignIn"),
 "login_no_mfa": ev("ConsoleLogin", "signin.amazonaws.com", user("jsmith"), None, {"ConsoleLogin": "Success"},
                    additionalEventData={"MFAUsed": "No"}, eventType="AwsConsoleSignIn"),
 "login_failed": ev("ConsoleLogin", "signin.amazonaws.com", user("jsmith"), None, {"ConsoleLogin": "Failure"},
                    additionalEventData={"MFAUsed": "No"}, errorMessage="Failed authentication", eventType="AwsConsoleSignIn"),
 "stop_logging": ev("StopLogging", "cloudtrail.amazonaws.com", user("deploy-bot"),
                    {"name": f"arn:aws:cloudtrail:us-east-1:{ACCT}:trail/org-trail"}),
 "delete_trail": ev("DeleteTrail", "cloudtrail.amazonaws.com", user("deploy-bot"), {"name": "org-trail"}),
 "guardduty_delete": ev("DeleteDetector", "guardduty.amazonaws.com", user("deploy-bot"),
                        {"detectorId": "12abc34d567e8fa901bc2d34e56789f0"}),
 "create_user": ev("CreateUser", "iam.amazonaws.com", user("deploy-bot"), {"userName": "support-backup"},
                   {"user": {"userName": "support-backup"}}),
 "create_access_key": ev("CreateAccessKey", "iam.amazonaws.com", user("deploy-bot"), {"userName": "support-backup"}),
 "attach_admin": ev("AttachUserPolicy", "iam.amazonaws.com", user("deploy-bot"),
                    {"userName": "support-backup", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
 "inline_admin": ev("PutRolePolicy", "iam.amazonaws.com", user("deploy-bot"),
                    {"roleName": "lambda-exec", "policyName": "temp-fix",
                     "policyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                         {"Effect": "Allow", "Action": "*", "Resource": "*"}]})}),
 "sg_open_ssh": ev("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", user("jsmith"),
                   {"groupId": "sg-0a1b2c3d4e5f67890", "ipPermissions": {"items": [
                       {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}),
 "sg_open_all": ev("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", user("jsmith"),
                   {"groupId": "sg-0fedcba9876543210", "ipPermissions": {"items": [
                       {"ipProtocol": "-1", "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]}}]}}),
 "s3_bpa_deleted": ev("DeleteBucketPublicAccessBlock", "s3.amazonaws.com", user("jsmith"),
                      {"bucketName": "acme-customer-exports", "Host": "acme-customer-exports.s3.amazonaws.com"}),
 "s3_public_policy": ev("PutBucketPolicy", "s3.amazonaws.com", user("jsmith"),
                        {"bucketName": "acme-customer-exports", "bucketPolicy": {"Version": "2012-10-17", "Statement": [
                            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                             "Resource": "arn:aws:s3:::acme-customer-exports/*"}]}}),
 "s3_public_acl": ev("PutBucketAcl", "s3.amazonaws.com", user("jsmith"),
                     {"bucketName": "acme-backups", "x-amz-acl": ["public-read"]}),
 "kms_schedule_delete": ev("ScheduleKeyDeletion", "kms.amazonaws.com", user("deploy-bot"),
                           {"keyId": "1234abcd-12ab-34cd-56ef-1234567890ab", "pendingWindowInDays": 7}),
}
benign = {
 "login_with_mfa": ev("ConsoleLogin", "signin.amazonaws.com", user("casimir"), None, {"ConsoleLogin": "Success"},
                      additionalEventData={"MFAUsed": "Yes"}, eventType="AwsConsoleSignIn"),
 "sso_login": ev("ConsoleLogin", "signin.amazonaws.com",
                 {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/AWSReservedSSO_Admin/casimir",
                  "accountId": ACCT}, None, {"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"},
                 eventType="AwsConsoleSignIn"),
 "describe_instances": ev("DescribeInstances", "ec2.amazonaws.com", user("casimir"), {"instancesSet": {}}),
 "sg_office_only": ev("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", user("casimir"),
                      {"groupId": "sg-0123", "ipPermissions": {"items": [
                          {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                           "ipRanges": {"items": [{"cidrIp": "198.51.100.10/32"}]}}]}}),
 "stop_logging_denied": ev("StopLogging", "cloudtrail.amazonaws.com", user("intern"), {"name": "org-trail"},
                           errorCode="AccessDenied", errorMessage="User is not authorized"),
 "s3_bpa_enabled": ev("PutBucketPublicAccessBlock", "s3.amazonaws.com", user("casimir"),
                      {"bucketName": "acme-logs", "PublicAccessBlockConfiguration": {
                          "BlockPublicAcls": True, "IgnorePublicAcls": True,
                          "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}),
 "attach_readonly": ev("AttachUserPolicy", "iam.amazonaws.com", user("casimir"),
                       {"userName": "auditor", "policyArn": "arn:aws:iam::aws:policy/SecurityAudit"}),
 "root_service_event": ev("ConsoleLogin", "signin.amazonaws.com", dict(ROOT, invokedBy="support.amazonaws.com"),
                          eventType="AwsServiceEvent"),
}
for folder, data in (("malicious", malicious), ("benign", benign)):
    os.makedirs(os.path.join(BASE, folder), exist_ok=True)
    for k, v in data.items():
        with open(os.path.join(BASE, folder, k + ".json"), "w") as f:
            json.dump(v, f, indent=2)
print(f"wrote {len(malicious)} malicious + {len(benign)} benign events")
