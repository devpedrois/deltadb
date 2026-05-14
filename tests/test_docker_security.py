"""Docker security verification tests.

These tests verify that the running containers meet hardening requirements:
- docker-compose config is valid
- PostgreSQL container Env does not expose POSTGRES_PASSWORD= in plaintext
- Containers run as non-root user

All tests are skipped when Docker or docker-compose is not available.
"""
import json
import subprocess

import pytest


def _check_cmd_works(*cmd: str) -> bool:
    try:
        return subprocess.run(list(cmd), capture_output=True, timeout=5).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_DOCKER_AVAILABLE = _check_cmd_works("docker", "version")
_COMPOSE_AVAILABLE = _check_cmd_works("docker-compose", "--version") or (
    _DOCKER_AVAILABLE and _check_cmd_works("docker", "compose", "version")
)


def _compose(*args: str) -> subprocess.CompletedProcess:
    if _check_cmd_works("docker-compose", "--version"):
        cmd = ["docker-compose", *args]
    else:
        cmd = ["docker", "compose", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def _get_pg_container_id() -> str | None:
    result = subprocess.run(
        ["docker", "ps", "--filter", "name=deltadb", "--filter", "name=postgres",
         "--format", "{{.ID}}"],
        capture_output=True, text=True,
    )
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return ids[0] if ids else None


@pytest.mark.docker_security
@pytest.mark.skipif(not _COMPOSE_AVAILABLE, reason="docker-compose not available")
def test_docker_compose_config_valid():
    result = _compose("config", "--quiet")
    assert result.returncode == 0, (
        f"docker-compose config failed:\n{result.stderr}"
    )


@pytest.mark.docker_security
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available")
def test_postgres_container_env_no_plaintext_password():
    container_id = _get_pg_container_id()
    if container_id is None:
        pytest.skip(
            "deltadb postgres container not running — start with make docker-up"
        )

    result = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"docker inspect failed: {result.stderr}"
    inspect_data = json.loads(result.stdout)
    env_vars: list[str] = inspect_data[0].get("Config", {}).get("Env", [])
    for env_var in env_vars:
        assert not env_var.startswith("POSTGRES_PASSWORD="), (
            f"Plaintext POSTGRES_PASSWORD found in container Env: {env_var}. "
            "Use POSTGRES_PASSWORD_FILE (Docker Secret) instead."
        )


@pytest.mark.docker_security
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="Docker not available")
def test_postgres_container_not_running_as_root():
    container_id = _get_pg_container_id()
    if container_id is None:
        pytest.skip(
            "deltadb postgres container not running — start with make docker-up"
        )

    result = subprocess.run(
        ["docker", "exec", container_id, "whoami"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"docker exec failed: {result.stderr}"
    user = result.stdout.strip()
    assert user != "root", (
        f"Container is running as root. Got: '{user}'. "
        "Containers must run as non-root user (uid 1001)."
    )
