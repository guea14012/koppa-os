"""KOPPA stdlib: cloud — AWS/GCP/Azure/DO cloud security testing."""
import urllib.request, urllib.error, json, re, subprocess, ssl

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


def _get(url, headers=None, timeout=5):
    hdrs = {"User-Agent": "curl/7.68.0"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
            return r.read().decode(errors="replace"), r.status
    except Exception:
        return "", 0


# ── AWS ───────────────────────────────────────────────────────────────────────
def aws_metadata(path=""):
    """Fetch AWS IMDS metadata (v1)."""
    body, code = _get(f"http://169.254.169.254/latest/meta-data/{path}")
    return body if code == 200 else ""

def aws_imdsv2_token():
    """Get IMDSv2 session token."""
    req = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode()
    except Exception:
        return ""

def aws_creds():
    """Extract IAM credentials from IMDS."""
    role = aws_metadata("iam/security-credentials/").strip()
    if not role:
        return {}
    body, code = _get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
    if code != 200:
        return {}
    try:
        data = json.loads(body)
        return {
            "role":       role,
            "key_id":     data.get("AccessKeyId"),
            "secret":     data.get("SecretAccessKey"),
            "token":      data.get("Token"),
            "expiry":     data.get("Expiration"),
        }
    except Exception:
        return {}

def aws_user_data():
    return aws_metadata("user-data")

def aws_all_metadata():
    keys = ["ami-id", "instance-id", "instance-type", "local-ipv4",
            "public-ipv4", "hostname", "security-groups",
            "placement/region", "placement/availability-zone"]
    result = {}
    for k in keys:
        v = aws_metadata(k).strip()
        if v:
            result[k] = v
    result["iam_creds"] = aws_creds()
    return result

def s3_enum(domain_or_name):
    """Check for open S3 buckets via URL patterns."""
    name = domain_or_name.replace(".", "-")
    variants = [
        f"{name}",
        f"{name}-backup",
        f"{name}-logs",
        f"{name}-dev",
        f"{name}-prod",
        f"{name}-staging",
        f"{name}-assets",
        f"{name}-media",
        f"{name}-static",
        f"{name}-uploads",
        f"{name}-data",
    ]
    found = []
    for bucket in variants:
        url = f"https://{bucket}.s3.amazonaws.com/"
        body, code = _get(url)
        if code in (200, 403):
            found.append({
                "bucket": bucket,
                "url":    url,
                "public": code == 200,
                "code":   code,
            })
    return found

def aws_key_test(access_key, secret_key, region="us-east-1"):
    """Test if AWS keys are valid."""
    return subprocess.getoutput(
        f"AWS_ACCESS_KEY_ID={access_key} AWS_SECRET_ACCESS_KEY={secret_key} "
        f"aws sts get-caller-identity --region {region} 2>&1"
    )

def aws_enum(access_key, secret_key, region="us-east-1"):
    """Enumerate AWS services with given keys."""
    prefix = f"AWS_ACCESS_KEY_ID={access_key} AWS_SECRET_ACCESS_KEY={secret_key} AWS_DEFAULT_REGION={region}"
    results = {}
    for svc, cmd in [
        ("identity",  "aws sts get-caller-identity"),
        ("s3_buckets","aws s3 ls"),
        ("ec2",       "aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress}'"),
        ("lambda",    "aws lambda list-functions --query 'Functions[].FunctionName'"),
        ("iam_users", "aws iam list-users --query 'Users[].UserName'"),
        ("secrets",   "aws secretsmanager list-secrets --query 'SecretList[].Name'"),
    ]:
        results[svc] = subprocess.getoutput(f"{prefix} {cmd} 2>/dev/null")
    return results


# ── GCP ───────────────────────────────────────────────────────────────────────
def gcp_metadata(path=""):
    """Fetch GCP metadata server."""
    url = f"http://metadata.google.internal/computeMetadata/v1/{path}"
    body, code = _get(url, headers={"Metadata-Flavor": "Google"})
    return body if code == 200 else ""

def gcp_service_account():
    return gcp_metadata("instance/service-accounts/default/email")

def gcp_token():
    data = gcp_metadata("instance/service-accounts/default/token")
    try:    return json.loads(data).get("access_token", "")
    except: return ""

def gcp_all_metadata():
    return {
        "project":         gcp_metadata("project/project-id"),
        "zone":            gcp_metadata("instance/zone"),
        "hostname":        gcp_metadata("instance/hostname"),
        "service_account": gcp_service_account(),
        "token":           gcp_token(),
    }


# ── Azure ─────────────────────────────────────────────────────────────────────
def azure_metadata():
    body, code = _get(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata": "true"}
    )
    if code != 200:
        return {}
    try:    return json.loads(body)
    except: return {}

def azure_token(resource="https://management.azure.com/"):
    body, code = _get(
        f"http://169.254.169.254/metadata/identity/oauth2/token"
        f"?api-version=2018-02-01&resource={resource}",
        headers={"Metadata": "true"}
    )
    if code != 200:
        return ""
    try:    return json.loads(body).get("access_token", "")
    except: return ""


# ── Generic ───────────────────────────────────────────────────────────────────
def detect_cloud():
    """Detect which cloud provider we're running in."""
    if aws_metadata("instance-id"):      return "aws"
    if gcp_metadata("instance/zone"):    return "gcp"
    if azure_metadata().get("compute"):  return "azure"
    return "unknown"

def key_scan_text(text):
    """Scan text blob for cloud API keys/secrets."""
    patterns = {
        "aws_access_key":   r"AKIA[0-9A-Z]{16}",
        "aws_secret":       r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]",
        "gcp_api_key":      r"AIza[0-9A-Za-z\-_]{35}",
        "azure_sas":        r"sv=\d{4}-\d{2}-\d{2}&ss=",
        "github_pat":       r"ghp_[A-Za-z0-9]{36}",
        "stripe_key":       r"sk_live_[0-9a-zA-Z]{24}",
        "twilio_sid":       r"AC[a-z0-9]{32}",
        "do_token":         r"dop_v1_[a-f0-9]{64}",
        "heroku_key":       r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "slack_token":      r"xox[baprs]-[A-Za-z0-9\-]+",
        "jwt":              r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "private_key":      r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    }
    found = {}
    for name, pat in patterns.items():
        hits = re.findall(pat, text)
        if hits:
            found[name] = hits
    return found
