import logging
import os
from pathlib import Path
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


def mask_url(url: str) -> str:
    # [SECURITY] Credential masking — urlparse handles passwords with special chars
    try:
        parsed = urlparse(str(url))
        if parsed.password:
            masked = parsed.netloc.replace(f":{parsed.password}@", ":****@", 1)
            return urlunparse(parsed._replace(netloc=masked))
    except Exception:
        pass
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
