import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def mask_url(url: str) -> str:
    # [SECURITY] Credential masking — raw string approach handles passwords with
    # special chars (@, #, ?) that confuse urlparse's authority splitting.
    try:
        raw = str(url)
        scheme_end = raw.find("://")
        if scheme_end == -1:
            return raw
        authority_start = scheme_end + 3
        path_start = raw.find("/", authority_start)
        if path_start != -1:
            authority = raw[authority_start:path_start]
            rest = raw[path_start:]
        else:
            authority = raw[authority_start:]
            rest = ""
        last_at = authority.rfind("@")
        if last_at == -1:
            return raw
        userinfo = authority[:last_at]
        host_part = authority[last_at:]
        colon_idx = userinfo.find(":")
        if colon_idx == -1:
            return raw
        user = userinfo[:colon_idx]
        return f"{raw[:authority_start]}{user}:****{host_part}{rest}"
    except Exception:
        return str(url)


def get_credential(env_var: str, secret_file_env: str | None = None) -> str | None:
    """Read credential preferring Docker Secret file over environment variable.

    # [SECURITY] Docker Secrets preferred: not visible in docker inspect,
    # ps aux, or logs. Env vars are fallback for local development only.
    """
    if secret_file_env:
        secret_path = os.environ.get(secret_file_env)
        if secret_path:
            p = Path(secret_path)
            if p.exists() and p.is_file():
                val = p.read_text(encoding="utf-8").strip()
                if val:
                    logger.debug(
                        "Credential loaded from Docker Secret: %s", secret_path
                    )
                    return val
    val = os.environ.get(env_var)
    if val:
        logger.debug("Credential loaded from environment variable: %s", env_var)
    return val
