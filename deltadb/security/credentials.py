import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def mask_url(url: str) -> str:
    # [SECURITY] Credential masking — anchor on last @ after scheme to correctly
    # handle passwords containing special chars (/, @, #, ?) including "://".
    # Finding the path separator BEFORE the last @ would truncate passwords with /.
    try:
        raw = str(url)
        scheme_end = raw.find("://")
        if scheme_end == -1:
            return raw
        authority_start = scheme_end + 3
        full_after_scheme = raw[authority_start:]

        # Find last @ — this is always the boundary between credentials and host
        last_at = full_after_scheme.rfind("@")
        if last_at == -1:
            return raw  # no credentials present

        # Find path separator AFTER the @, so / inside passwords don't fool us
        path_in_rest = full_after_scheme.find("/", last_at)
        if path_in_rest != -1:
            authority = full_after_scheme[:path_in_rest]
            rest = full_after_scheme[path_in_rest:]
        else:
            authority = full_after_scheme
            rest = ""

        # authority = "user:password@host:port" — mask the password
        at_in_authority = authority.rfind("@")
        credentials = authority[:at_in_authority]
        host_part = authority[at_in_authority:]  # "@host:port"

        colon_idx = credentials.find(":")
        if colon_idx == -1:
            masked_credentials = credentials  # no password, just username
        else:
            user = credentials[:colon_idx]
            masked_credentials = user + ":****"

        return raw[:authority_start] + masked_credentials + host_part + rest
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
