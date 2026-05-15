import logging

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
        # [SECURITY] Do NOT return str(url) — if the object's __str__ embeds
        # a raw connection string, the fallback leaks credentials. Return a
        # safe placeholder instead. Callers must treat this as an opaque token.
        logger.debug("mask_url: failed to mask URL, returning redacted placeholder")
        return "[CREDENTIAL REDACTED]"
