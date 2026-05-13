import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: mark test as requiring real database containers"
    )


@pytest.fixture(scope="session")
def pg_url():
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16.3-alpine3.20") as pg:
        yield pg.get_connection_url()


@pytest.fixture(scope="session")
def mysql_url():
    from testcontainers.mysql import MySqlContainer

    with MySqlContainer("mysql:8.0.37") as mysql:
        # [SECURITY] Force pymysql driver — mysqldb not installed
        url = mysql.get_connection_url()
        yield url.replace("mysql://", "mysql+pymysql://", 1)
