"""
utils/secrets.py — AWS Secrets Manager integration

Provides get_secret() which:
  1. Tries AWS Secrets Manager first (when in production)
  2. Falls back to environment variables (for local dev and CI)

This is the FTR-compliant way to manage secrets — no plaintext secrets
in .env files on production servers.

Setup:
  1. Create a secret in AWS Secrets Manager:
       aws secretsmanager create-secret \
         --name shieldscan/production/secrets \
         --secret-string '{"JWT_SECRET_KEY":"...","AWS_ENCRYPTION_KEY":"...","GROQ_API_KEY":"..."}'
  2. Grant the EC2 instance profile the secretsmanager:GetSecretValue permission
  3. Set SECRETS_MANAGER_SECRET_NAME=shieldscan/production/secrets in .env

Usage:
    from .utils.secrets import get_secret
    jwt_key = get_secret("JWT_SECRET_KEY")
"""

import os
import json
import logging

logger = logging.getLogger(__name__)

_SECRET_CACHE: dict = {}
_CACHE_LOADED = False


def _load_from_secrets_manager() -> dict:
    """
    Fetch all secrets from a single Secrets Manager secret (JSON object).
    Returns empty dict if Secrets Manager is not configured or unavailable.
    """
    secret_name = os.getenv("SECRETS_MANAGER_SECRET_NAME", "").strip()
    if not secret_name:
        return {}

    try:
        import boto3
        region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-west-1"))
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=secret_name)
        secrets = json.loads(response["SecretString"])
        logger.info(
            "Loaded %d secrets from AWS Secrets Manager: %s",
            len(secrets), secret_name,
        )
        return secrets
    except ImportError:
        logger.warning("boto3 not installed — cannot load from Secrets Manager")
        return {}
    except Exception as exc:
        logger.warning(
            "Secrets Manager unavailable (%s: %s) — falling back to environment variables",
            type(exc).__name__, exc,
        )
        return {}


def _ensure_loaded():
    """Load secrets from Secrets Manager once per process startup."""
    global _SECRET_CACHE, _CACHE_LOADED
    if not _CACHE_LOADED:
        _SECRET_CACHE = _load_from_secrets_manager()
        _CACHE_LOADED = True


def get_secret(key: str, default: str = "") -> str:
    """
    Get a secret value with this priority:
      1. AWS Secrets Manager (if SECRETS_MANAGER_SECRET_NAME is set)
      2. Environment variable with the same name
      3. Provided default (empty string if not given)

    Args:
        key: The secret name (e.g. "JWT_SECRET_KEY")
        default: Fallback value if not found anywhere

    Returns:
        The secret value as a string
    """
    _ensure_loaded()

    # 1. Secrets Manager
    if key in _SECRET_CACHE:
        return str(_SECRET_CACHE[key])

    # 2. Environment variable
    value = os.getenv(key, default)
    return value


def reload_secrets():
    """
    Force a reload from Secrets Manager (e.g. after a secret rotation).
    Call this from a background task or admin endpoint.
    """
    global _CACHE_LOADED
    _CACHE_LOADED = False
    _ensure_loaded()
