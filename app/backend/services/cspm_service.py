"""
cspm_service.py — Cloud Security Posture Management
Owner: Kiran

Scans an AWS account for misconfigurations using boto3.
Requires: SecurityAudit managed policy on the IAM user.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INTERFACE CONTRACT — do not change the function signature.
scan_manager.py calls run_cspm_scan() and expects this exact return shape.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Expected return: list of dicts, each with these keys:
    {
        "finding_id":        str,   # unique ID e.g. "CSPM-S3-PUBLIC-my-bucket"
        "finding_type":      str,   # always "CSPM"
        "severity":          str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        "title":             str,   # short description
        "description":       str,   # detailed explanation
        "resource":          str,   # ARN or resource name
        "region":            str,   # AWS region or "global"
        "fix_recommendation":str,   # how to fix it
    }
"""

import csv
import io
import time
import logging
import functools

logger = logging.getLogger(__name__)

USE_MOCK_CSPM = False  # Real boto3 implementation active


# ── Retry decorator for boto3 calls ────────────────────────────────────────────
# Retries on transient AWS errors (throttling, temporary network issues).
# FTR requires retry logic with exponential backoff on all external calls.

def _aws_retry(max_attempts: int = 3, base_delay: float = 0.5):
    """
    Decorator: retry on AWS ClientError (throttling / transient) with exponential backoff.
    Passes through all other exceptions immediately.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    type(exc).__name__
                    exc_str = str(exc)
                    # Retry on throttling or rate-limit errors only
                    is_throttle = (
                        "ThrottlingException" in exc_str
                        or "RequestLimitExceeded" in exc_str
                        or "TooManyRequestsException" in exc_str
                        or "SlowDown" in exc_str
                    )
                    if is_throttle and attempt < max_attempts - 1:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(
                            "%s throttled — retry %d/%d in %.1fs",
                            func.__name__, attempt + 1, max_attempts, delay,
                        )
                        time.sleep(delay)
                        last_exc = exc
                    else:
                        raise  # non-throttle error or final attempt — propagate
            raise last_exc  # type: ignore
        return wrapper
    return decorator


# ── Mock data (used if USE_MOCK_CSPM = True) ─────────────────────────────────
MOCK_FINDINGS = [
    {
        "finding_id": "CSPM-S3-PUBLIC-demo-bucket",
        "finding_type": "CSPM",
        "severity": "HIGH",
        "title": "S3 bucket 'demo-bucket' has public access enabled",
        "description": "The S3 bucket 'demo-bucket' does not have all public access block settings enabled.",
        "resource": "s3://demo-bucket",
        "region": "us-east-1",
        "fix_recommendation": "Enable all S3 Block Public Access settings via AWS Console.",
    },
    {
        "finding_id": "CSPM-IAM-ROOT-KEY",
        "finding_type": "CSPM",
        "severity": "CRITICAL",
        "title": "Root account has active access keys",
        "description": "The AWS root account has active programmatic access keys.",
        "resource": "arn:aws:iam::root",
        "region": "global",
        "fix_recommendation": "Delete root access keys: AWS Console → Account → Security credentials.",
    },
    {
        "finding_id": "CSPM-EC2-SSH-sg-00000000",
        "finding_type": "CSPM",
        "severity": "HIGH",
        "title": "Security group allows SSH from anywhere",
        "description": "A security group allows inbound SSH (port 22) from 0.0.0.0/0.",
        "resource": "sg-00000000",
        "region": "us-east-1",
        "fix_recommendation": "Restrict SSH to known IP ranges only.",
    },
]


# ── Real boto3 checks ─────────────────────────────────────────────────────────

@_aws_retry(max_attempts=3)
def _check_s3_public_access(session, region: str) -> list[dict]:
    """Check all S3 buckets for public access block misconfigurations."""
    findings = []
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                resp = s3.get_public_access_block(Bucket=name)
                config = resp["PublicAccessBlockConfiguration"]
                fully_blocked = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ])
                if not fully_blocked:
                    off = [k for k, v in {
                        "BlockPublicAcls": config.get("BlockPublicAcls"),
                        "IgnorePublicAcls": config.get("IgnorePublicAcls"),
                        "BlockPublicPolicy": config.get("BlockPublicPolicy"),
                        "RestrictPublicBuckets": config.get("RestrictPublicBuckets"),
                    }.items() if not v]
                    findings.append({
                        "finding_id": f"CSPM-S3-PUBLIC-{name}",
                        "finding_type": "CSPM",
                        "severity": "HIGH",
                        "title": f"S3 bucket '{name}' has public access enabled",
                        "description": (
                            f"Bucket '{name}' has the following Block Public Access settings disabled: "
                            f"{', '.join(off)}. This may expose stored data to the internet."
                        ),
                        "resource": f"s3://{name}",
                        "region": region,
                        "fix_recommendation": (
                            f"Enable all Block Public Access settings: "
                            f"AWS Console → S3 → {name} → Permissions → Block public access → Edit → check all 4 boxes."
                        ),
                    })
            except Exception as e:
                # NoSuchPublicAccessBlockConfiguration means no block config at all
                if hasattr(e, "response") and e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "finding_id": f"CSPM-S3-NOPAB-{name}",
                        "finding_type": "CSPM",
                        "severity": "HIGH",
                        "title": f"S3 bucket '{name}' has no public access block configured",
                        "description": (
                            f"Bucket '{name}' has no Block Public Access configuration. "
                            "Without this, bucket policies or ACLs could expose objects to the internet."
                        ),
                        "resource": f"s3://{name}",
                        "region": region,
                        "fix_recommendation": (
                            f"Enable Block Public Access: "
                            f"AWS Console → S3 → {name} → Permissions → Block public access → Edit → check all 4 boxes."
                        ),
                    })
                else:
                    logger.debug(f"S3 check skipped for {name}: {e}")
    except Exception as e:
        logger.warning(f"S3 scan failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_iam_root(session) -> list[dict]:
    """Check root account for active access keys and missing MFA."""
    findings = []
    try:
        iam = session.client("iam")
        # Generate credential report
        for _ in range(6):
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
            time.sleep(1)

        report_resp = iam.get_credential_report()
        content = report_resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            if row.get("user") != "<root_account>":
                continue
            if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                findings.append({
                    "finding_id": "CSPM-IAM-ROOT-KEY",
                    "finding_type": "CSPM",
                    "severity": "CRITICAL",
                    "title": "Root account has active access keys",
                    "description": (
                        "The AWS root account has active programmatic access keys. "
                        "Root keys have unrestricted access to every service and resource — "
                        "a leaked root key means full account compromise."
                    ),
                    "resource": "arn:aws:iam::root",
                    "region": "global",
                    "fix_recommendation": (
                        "Delete root access keys immediately: "
                        "AWS Console → top-right account menu → Security credentials → "
                        "Access keys → Delete both keys."
                    ),
                })
            if row.get("mfa_active") == "false":
                findings.append({
                    "finding_id": "CSPM-IAM-ROOT-MFA",
                    "finding_type": "CSPM",
                    "severity": "CRITICAL",
                    "title": "Root account does not have MFA enabled",
                    "description": (
                        "The AWS root account has no multi-factor authentication. "
                        "Anyone who obtains the root password gains unrestricted control of the entire account."
                    ),
                    "resource": "arn:aws:iam::root",
                    "region": "global",
                    "fix_recommendation": (
                        "Enable MFA on root: AWS Console → top-right account menu → "
                        "Security credentials → Multi-factor authentication → Assign MFA device."
                    ),
                })
    except Exception as e:
        logger.warning(f"IAM root check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_iam_users_mfa(session) -> list[dict]:
    """
    Check all IAM users for missing MFA — both console and programmatic users.

    Severity logic:
    - MEDIUM  → console-only user with no MFA (phishable password)
    - MEDIUM  → programmatic-only user (access keys) with no MFA
    - HIGH    → user has BOTH console + active access keys but no MFA
    """
    findings = []
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # Console access?
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except Exception:
                    has_console = False

                # Active access keys?
                try:
                    keys_resp = iam.list_access_keys(UserName=username)
                    active_keys = [
                        k for k in keys_resp.get("AccessKeyMetadata", [])
                        if k["Status"] == "Active"
                    ]
                    has_active_keys = bool(active_keys)
                except Exception:
                    has_active_keys = False

                # Skip users with no access at all
                if not has_console and not has_active_keys:
                    continue

                # MFA devices
                mfa_resp = iam.list_mfa_devices(UserName=username)
                if mfa_resp.get("MFADevices"):
                    continue   # MFA present — pass

                # Build finding based on access type
                if has_console and has_active_keys:
                    severity = "HIGH"
                    title = f"IAM user '{username}' has console + API access but no MFA"
                    description = (
                        f"IAM user '{username}' has both AWS Console login and active access keys "
                        "but no MFA device. A single compromised credential grants full interactive "
                        "and programmatic access to your AWS account."
                    )
                elif has_console:
                    severity = "MEDIUM"
                    title = f"IAM user '{username}' has console access but no MFA"
                    description = (
                        f"IAM user '{username}' can log into the AWS Console but has no MFA device. "
                        "Password-only console access is vulnerable to credential theft and phishing."
                    )
                else:
                    severity = "MEDIUM"
                    title = f"IAM user '{username}' has active access keys but no MFA"
                    description = (
                        f"IAM user '{username}' has {len(active_keys)} active access key(s) "
                        "but no MFA device configured. Stolen access keys grant unrestricted API "
                        "access with no second factor required."
                    )

                findings.append({
                    "finding_id": f"CSPM-IAM-USER-MFA-{username}",
                    "finding_type": "CSPM",
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "resource": f"arn:aws:iam::user/{username}",
                    "region": "global",
                    "fix_recommendation": (
                        f"Enable MFA for '{username}': AWS Console → IAM → Users → "
                        f"{username} → Security credentials → Assign MFA device. "
                        "For service accounts, enforce MFA via IAM policy conditions."
                    ),
                })
    except Exception as e:
        logger.warning(f"IAM users MFA check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_ec2_open_ports(session, region: str) -> list[dict]:
    """Check security groups for dangerous open ports exposed to 0.0.0.0/0."""
    findings = []
    DANGEROUS_PORTS = {
        22:    ("SSH",         "HIGH"),
        3389:  ("RDP",         "HIGH"),
        3306:  ("MySQL",       "MEDIUM"),
        5432:  ("PostgreSQL",  "MEDIUM"),
        27017: ("MongoDB",     "MEDIUM"),
        6379:  ("Redis",       "MEDIUM"),
    }
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_security_groups")
        seen = set()
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    for port, (service, severity) in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            open_to_world = any(
                                r.get("CidrIp") in ("0.0.0.0/0",)
                                for r in perm.get("IpRanges", [])
                            ) or any(
                                r.get("CidrIpv6") == "::/0"
                                for r in perm.get("Ipv6Ranges", [])
                            )
                            if open_to_world:
                                fid = f"CSPM-EC2-{service}-{sg_id}"
                                if fid not in seen:
                                    seen.add(fid)
                                    findings.append({
                                        "finding_id": fid,
                                        "finding_type": "CSPM",
                                        "severity": severity,
                                        "title": f"Security group '{sg_name}' allows {service} (port {port}) from anywhere",
                                        "description": (
                                            f"Security group {sg_id} ({sg_name}) allows inbound {service} traffic "
                                            f"on port {port} from 0.0.0.0/0, exposing instances to attacks from the public internet."
                                        ),
                                        "resource": sg_id,
                                        "region": region,
                                        "fix_recommendation": (
                                            f"Restrict port {port} in security group {sg_id}: "
                                            f"AWS Console → EC2 → Security Groups → {sg_id} → "
                                            f"Inbound rules → Edit → change source from 0.0.0.0/0 to your specific IP or CIDR."
                                        ),
                                    })
    except Exception as e:
        logger.warning(f"EC2 security group check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_cloudtrail(session, region: str) -> list[dict]:
    """Check if CloudTrail is enabled and logging in the given region."""
    findings = []
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            findings.append({
                "finding_id": f"CSPM-CLOUDTRAIL-DISABLED-{region}",
                "finding_type": "CSPM",
                "severity": "MEDIUM",
                "title": f"CloudTrail is not enabled in {region}",
                "description": (
                    f"No CloudTrail trails found in region {region}. "
                    "Without CloudTrail, AWS API activity is not logged and security incidents cannot be investigated."
                ),
                "resource": f"cloudtrail:{region}",
                "region": region,
                "fix_recommendation": (
                    "Enable CloudTrail: AWS Console → CloudTrail → Create trail → "
                    "enable for all regions → store logs in an S3 bucket."
                ),
            })
        else:
            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if not status.get("IsLogging", True):
                        findings.append({
                            "finding_id": f"CSPM-CLOUDTRAIL-NOTLOGGING-{trail['Name']}",
                            "finding_type": "CSPM",
                            "severity": "MEDIUM",
                            "title": f"CloudTrail trail '{trail['Name']}' is not logging",
                            "description": (
                                f"CloudTrail trail '{trail['Name']}' exists but logging is currently disabled. "
                                "API activity during this period will not be recorded."
                            ),
                            "resource": trail.get("TrailARN", trail["Name"]),
                            "region": region,
                            "fix_recommendation": (
                                f"Enable logging: AWS Console → CloudTrail → Trails → "
                                f"{trail['Name']} → Start logging."
                            ),
                        })
                except Exception as e:
                    logger.debug(f"CloudTrail status check skipped for {trail['Name']}: {e}")
    except Exception as e:
        logger.warning(f"CloudTrail check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_password_policy(session) -> list[dict]:
    """Check IAM account password policy for weak settings."""
    findings = []
    try:
        iam = session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append("minimum length < 14 characters")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("uppercase letters not required")
            if not policy.get("RequireLowercaseCharacters"):
                issues.append("lowercase letters not required")
            if not policy.get("RequireNumbers"):
                issues.append("numbers not required")
            if not policy.get("RequireSymbols"):
                issues.append("symbols not required")
            if not policy.get("MaxPasswordAge") or policy.get("MaxPasswordAge", 999) > 90:
                issues.append("password expiry > 90 days or not enforced")
            if not policy.get("PasswordReusePrevention") or policy.get("PasswordReusePrevention", 0) < 24:
                issues.append("password reuse prevention < 24 previous passwords")

            if issues:
                findings.append({
                    "finding_id": "CSPM-IAM-PASSWORD-POLICY",
                    "finding_type": "CSPM",
                    "severity": "LOW",
                    "title": "IAM password policy does not meet best practices",
                    "description": (
                        f"The IAM account password policy has weaknesses: {'; '.join(issues)}. "
                        "Weak policies increase the risk of credential compromise."
                    ),
                    "resource": "arn:aws:iam::account-password-policy",
                    "region": "global",
                    "fix_recommendation": (
                        "Strengthen password policy: AWS Console → IAM → Account settings → "
                        "Password policy → Edit. Set min length 14, require all character types, "
                        "90-day expiry, 24 password history."
                    ),
                })
        except Exception as inner:
            if hasattr(inner, "response") and inner.response.get("Error", {}).get("Code") == "NoSuchEntity":
                findings.append({
                    "finding_id": "CSPM-IAM-NO-PASSWORD-POLICY",
                    "finding_type": "CSPM",
                    "severity": "MEDIUM",
                    "title": "No IAM account password policy configured",
                    "description": (
                        "No custom IAM password policy is set. AWS applies minimal defaults, "
                        "allowing weak passwords for IAM users with console access."
                    ),
                    "resource": "arn:aws:iam::account-password-policy",
                    "region": "global",
                    "fix_recommendation": (
                        "Set a password policy: AWS Console → IAM → Account settings → "
                        "Password policy → Set password policy."
                    ),
                })
    except Exception as e:
        logger.warning(f"Password policy check failed: {e}")
    return findings


# ── Additional checks ────────────────────────────────────────────────────────

@_aws_retry(max_attempts=3)
def _check_ebs_encryption(session, region: str) -> list[dict]:
    """Flag EBS volumes that are not encrypted at rest."""
    findings = []
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted", False):
                    vol_id = vol["VolumeId"]
                    size_gb = vol.get("Size", "?")
                    state = vol.get("State", "unknown")
                    # Skip volumes in error/deleted state
                    if state in ("deleting", "deleted"):
                        continue
                    findings.append({
                        "finding_id": f"CSPM-EBS-UNENCRYPTED-{vol_id}",
                        "finding_type": "CSPM",
                        "severity": "MEDIUM",
                        "title": f"EBS volume '{vol_id}' ({size_gb} GB) is not encrypted",
                        "description": (
                            f"EBS volume {vol_id} ({size_gb} GB, state: {state}) stores data without "
                            "encryption at rest. If the underlying physical media is accessed, data "
                            "is readable without credentials."
                        ),
                        "resource": vol_id,
                        "region": region,
                        "fix_recommendation": (
                            f"EBS volumes cannot be encrypted in-place. Create an encrypted snapshot "
                            f"of {vol_id} and restore it as a new encrypted volume: "
                            "EC2 → Volumes → Create Snapshot → Copy Snapshot (enable encryption) → "
                            "Create Volume from the encrypted snapshot."
                        ),
                    })
    except Exception as e:
        logger.warning(f"EBS encryption check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_rds_encryption(session, region: str) -> list[dict]:
    """Flag RDS instances without storage encryption."""
    findings = []
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                if not db.get("StorageEncrypted", False):
                    db_id = db["DBInstanceIdentifier"]
                    engine = db.get("Engine", "unknown")
                    engine_ver = db.get("EngineVersion", "")
                    db_class = db.get("DBInstanceClass", "")
                    findings.append({
                        "finding_id": f"CSPM-RDS-UNENCRYPTED-{db_id}",
                        "finding_type": "CSPM",
                        "severity": "HIGH",
                        "title": f"RDS instance '{db_id}' ({engine}) is not encrypted",
                        "description": (
                            f"RDS instance '{db_id}' running {engine} {engine_ver} on {db_class} "
                            "has storage encryption disabled. Database files, automated backups, "
                            "and snapshots are all stored unencrypted."
                        ),
                        "resource": f"arn:aws:rds:{region}::db:{db_id}",
                        "region": region,
                        "fix_recommendation": (
                            f"RDS encryption must be set at creation time. To encrypt '{db_id}': "
                            "take a snapshot → copy snapshot with encryption enabled → restore "
                            "from the encrypted snapshot → update your connection strings → "
                            "delete the unencrypted instance."
                        ),
                    })
    except Exception as e:
        logger.warning(f"RDS encryption check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_vpc_flow_logs(session, region: str) -> list[dict]:
    """Flag VPCs that have no active flow logs."""
    findings = []
    try:
        ec2 = session.client("ec2")
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        if not vpcs:
            return findings

        fl_resp = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-type", "Values": ["VPC"]}]
        )
        active_vpc_ids = {
            fl["ResourceId"]
            for fl in fl_resp.get("FlowLogs", [])
            if fl.get("FlowLogStatus") == "ACTIVE"
        }

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            if vpc_id not in active_vpc_ids:
                is_default = vpc.get("IsDefault", False)
                name_tag = next(
                    (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), vpc_id
                )
                findings.append({
                    "finding_id": f"CSPM-VPC-FLOWLOGS-{vpc_id}",
                    "finding_type": "CSPM",
                    "severity": "MEDIUM",
                    "title": f"VPC '{name_tag}' has no flow logs enabled",
                    "description": (
                        f"VPC {vpc_id} ('{name_tag}'{', default VPC' if is_default else ''}) has no "
                        "active VPC Flow Logs. Without flow logs, there is no record of what IP traffic "
                        "entered or left your network — making incident investigation impossible."
                    ),
                    "resource": vpc_id,
                    "region": region,
                    "fix_recommendation": (
                        f"Enable flow logs: VPC Console → Your VPCs → select {vpc_id} → "
                        "Flow logs tab → Create flow log. Choose CloudWatch Logs or S3 as destination. "
                        "Select 'All' for traffic filter to capture accepted and rejected traffic."
                    ),
                })
    except Exception as e:
        logger.warning(f"VPC flow logs check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_s3_access_logging(session, region: str) -> list[dict]:
    """Flag S3 buckets with server access logging disabled."""
    findings = []
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                resp = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in resp:
                    findings.append({
                        "finding_id": f"CSPM-S3-LOGGING-{name}",
                        "finding_type": "CSPM",
                        "severity": "LOW",
                        "title": f"S3 bucket '{name}' has access logging disabled",
                        "description": (
                            f"S3 bucket '{name}' does not have server access logging enabled. "
                            "Without access logs, you cannot audit who accessed objects, "
                            "detect data exfiltration, or investigate suspicious activity."
                        ),
                        "resource": f"s3://{name}",
                        "region": region,
                        "fix_recommendation": (
                            f"Enable access logging: S3 Console → {name} → Properties → "
                            "Server access logging → Edit → Enable. Choose a target bucket "
                            "(a separate bucket is recommended) and a log prefix."
                        ),
                    })
            except Exception as e:
                logger.debug(f"S3 logging check skipped for {name}: {e}")
    except Exception as e:
        logger.warning(f"S3 access logging check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_iam_admin_policies(session) -> list[dict]:
    """Flag IAM users with AdministratorAccess policy attached directly."""
    findings = []
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                try:
                    attached = iam.list_attached_user_policies(UserName=username)
                    for policy in attached.get("AttachedPolicies", []):
                        if policy["PolicyName"] == "AdministratorAccess":
                            findings.append({
                                "finding_id": f"CSPM-IAM-ADMIN-{username}",
                                "finding_type": "CSPM",
                                "severity": "HIGH",
                                "title": f"IAM user '{username}' has AdministratorAccess attached",
                                "description": (
                                    f"IAM user '{username}' has the AdministratorAccess managed policy "
                                    "attached directly. This grants full access to all AWS services "
                                    "and resources, with no restrictions. The principle of least "
                                    "privilege requires users have only the permissions they need."
                                ),
                                "resource": f"arn:aws:iam::user/{username}",
                                "region": "global",
                                "fix_recommendation": (
                                    f"Replace AdministratorAccess on '{username}' with a scoped policy: "
                                    f"IAM → Users → {username} → Permissions → Detach AdministratorAccess → "
                                    "Attach a policy limited to the services this user actually needs."
                                ),
                            })
                except Exception as e:
                    logger.debug(f"IAM admin policy check skipped for {username}: {e}")
    except Exception as e:
        logger.warning(f"IAM admin policy check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_kms_rotation(session, region: str) -> list[dict]:
    """Flag customer-managed KMS keys without annual rotation enabled."""
    findings = []
    try:
        kms = session.client("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    # Only customer-managed, enabled, symmetric keys can be rotated
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    if meta.get("KeyState") != "Enabled":
                        continue
                    if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                        continue  # Asymmetric keys can't be auto-rotated
                    rotation = kms.get_key_rotation_status(KeyId=key_id)
                    if not rotation.get("KeyRotationEnabled", False):
                        alias = key_id
                        try:
                            aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                            if aliases:
                                alias = aliases[0].get("AliasName", key_id)
                        except Exception:
                            pass
                        findings.append({
                            "finding_id": f"CSPM-KMS-ROTATION-{key_id}",
                            "finding_type": "CSPM",
                            "severity": "LOW",
                            "title": f"KMS key '{alias}' has automatic rotation disabled",
                            "description": (
                                f"Customer-managed KMS key '{alias}' ({key_id}) does not have "
                                "automatic annual key rotation enabled. Using the same key material "
                                "indefinitely increases risk if the key is ever compromised."
                            ),
                            "resource": f"arn:aws:kms:{region}::key/{key_id}",
                            "region": region,
                            "fix_recommendation": (
                                f"Enable rotation: KMS Console → Customer managed keys → {alias} → "
                                "Key rotation → Edit → Enable automatic key rotation annually. "
                                "AWS replaces the key material each year while keeping the same Key ID."
                            ),
                        })
                except Exception as e:
                    logger.debug(f"KMS key check skipped for {key_id}: {e}")
    except Exception as e:
        logger.warning(f"KMS rotation check failed: {e}")
    return findings


@_aws_retry(max_attempts=3)
def _check_guardduty(session, region: str) -> list[dict]:
    """
    Check if GuardDuty is enabled and pull active medium/high/critical findings.
    If GuardDuty is not enabled, emit a MEDIUM finding.
    """
    findings = []
    try:
        gd = session.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])

        if not detectors:
            findings.append({
                "finding_id": f"CSPM-GUARDDUTY-DISABLED-{region}",
                "finding_type": "CSPM",
                "severity": "MEDIUM",
                "title": f"Amazon GuardDuty is not enabled in {region}",
                "description": (
                    f"GuardDuty is not enabled in {region}. GuardDuty continuously monitors "
                    "CloudTrail, VPC flow logs, and DNS logs for malicious activity and "
                    "unauthorized behavior. Without it, threats like credential compromise "
                    "or crypto-mining go undetected."
                ),
                "resource": f"guardduty:{region}",
                "region": region,
                "fix_recommendation": (
                    "Enable GuardDuty: AWS Console → GuardDuty → Get Started → Enable GuardDuty. "
                    "The 30-day free trial covers most accounts. After that, cost is based on "
                    "data volume processed."
                ),
            })
            return findings

        detector_id = detectors[0]

        # Pull non-archived findings with severity >= 4 (Medium and above)
        response = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "severity": {"Gte": 4},
                    "service.archived": {"Eq": ["false"]},
                }
            },
            MaxResults=50,
        )
        finding_ids = response.get("FindingIds", [])

        if not finding_ids:
            return findings  # GuardDuty enabled, no active threats

        gd_findings_resp = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids,
        )

        SEVERITY_MAP = {
            (0, 4): "LOW",
            (4, 7): "MEDIUM",
            (7, 9): "HIGH",
            (9, 11): "CRITICAL",
        }

        for f in gd_findings_resp.get("Findings", []):
            sev_num = f.get("Severity", 0)
            sev = next(
                (v for (lo, hi), v in SEVERITY_MAP.items() if lo <= sev_num < hi),
                "MEDIUM"
            )
            short_id = f["Id"][:16]
            findings.append({
                "finding_id": f"CSPM-GD-{short_id}",
                "finding_type": "CSPM",
                "severity": sev,
                "title": f"[GuardDuty] {f.get('Title', 'Threat detected')}",
                "description": f.get("Description", "GuardDuty detected suspicious activity."),
                "resource": f.get("AccountId", "AWS account"),
                "region": f.get("Region", region),
                "fix_recommendation": (
                    f"Investigate in GuardDuty console: GuardDuty → Findings → filter by finding ID "
                    f"{f['Id']}. Review the affected resource and follow the recommended remediation."
                ),
            })
    except Exception as e:
        logger.warning(f"GuardDuty check failed: {e}")
    return findings


# ── Public entry point ────────────────────────────────────────────────────────

def run_cspm_scan(aws_access_key: str, aws_secret_key: str, region: str) -> list[dict]:
    """
    Scan an AWS account for security misconfigurations.

    Args:
        aws_access_key: IAM user access key (SecurityAudit policy required)
        aws_secret_key: IAM user secret key
        region: Primary AWS region to scan (e.g. "us-east-1")

    Returns:
        List of finding dicts matching the contract above.
    """
    if USE_MOCK_CSPM:
        return MOCK_FINDINGS

    import boto3

    scan_region = region or "us-east-1"
    session = boto3.Session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=scan_region,
    )

    findings = []

    logger.info("CSPM: scanning S3 public access...")
    findings.extend(_check_s3_public_access(session, scan_region))

    logger.info("CSPM: scanning IAM root account...")
    findings.extend(_check_iam_root(session))

    logger.info("CSPM: scanning IAM users MFA...")
    findings.extend(_check_iam_users_mfa(session))

    logger.info("CSPM: scanning IAM admin policies...")
    findings.extend(_check_iam_admin_policies(session))

    logger.info("CSPM: scanning EC2 security groups...")
    findings.extend(_check_ec2_open_ports(session, scan_region))

    logger.info("CSPM: scanning CloudTrail...")
    findings.extend(_check_cloudtrail(session, scan_region))

    logger.info("CSPM: scanning password policy...")
    findings.extend(_check_password_policy(session))

    logger.info("CSPM: scanning EBS encryption...")
    findings.extend(_check_ebs_encryption(session, scan_region))

    logger.info("CSPM: scanning RDS encryption...")
    findings.extend(_check_rds_encryption(session, scan_region))

    logger.info("CSPM: scanning VPC flow logs...")
    findings.extend(_check_vpc_flow_logs(session, scan_region))

    logger.info("CSPM: scanning S3 access logging...")
    findings.extend(_check_s3_access_logging(session, scan_region))

    logger.info("CSPM: scanning KMS key rotation...")
    findings.extend(_check_kms_rotation(session, scan_region))

    logger.info("CSPM: scanning GuardDuty status...")
    findings.extend(_check_guardduty(session, scan_region))

    logger.info(f"CSPM: scan complete — {len(findings)} findings")
    return findings
