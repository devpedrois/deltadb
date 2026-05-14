# deltadb

A production-ready schema diff and SQL migration generator for PostgreSQL, MySQL, and SQLite — built with defense-in-depth security, dialect-aware Jinja2 templates, and topological ordering by foreign key dependencies.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Coverage](https://img.shields.io/badge/coverage-93%25-brightgreen)
![Security](https://img.shields.io/badge/bandit-passing-brightgreen)

---

## 📋 Table of Contents

- [About](#-about)
- [Pipeline](#-pipeline)
- [Stack](#-stack)
- [Security](#-security)
- [Prerequisites](#-prerequisites)
- [Getting Started](#-getting-started)
- [CLI Reference](#-cli-reference)
- [YAML Schema Format](#-yaml-schema-format)
- [Dialects](#-dialects)
- [Safety Features](#-safety-features)
- [Testing](#-testing)
- [Environment Variables](#-environment-variables)
- [Project Structure](#-project-structure)
- [Design Decisions](#-design-decisions)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 About

**deltadb** compares two database schemas — live connections or YAML files — and produces a ready-to-run SQL migration with `UP` and `DOWN` blocks.

Key capabilities:

- Multi-source diffing: connect strings (`postgresql://...`) and YAML schemas as both source and target
- Dialect-aware SQL generation via Jinja2 templates for PostgreSQL, MySQL, and SQLite
- Topological ordering by foreign key dependencies — `DROP TABLE` order is always safe
- Rename detection using `difflib.SequenceMatcher` (opt-in, configurable threshold)
- Destructive operation markers (`-- WARNING: DESTRUCTIVE`) and a `--no-destructive` flag
- Defense-in-depth security across 9 independent layers: YAML safety, SQL identifier injection prevention, sandboxed templates, credential masking, path traversal prevention, and more
- Rich terminal diff output and JSON export

---

## 🏗️ Pipeline

### deltadb diff

```
[Source: DB or YAML]                     [Target: DB or YAML]
         |                                        |
    [Loader]                                 [Loader]
         |                                        |
  [SchemaModel A] --------> [Diff Engine] <------ [SchemaModel B]
                                   |
                          [list[Change]]
                                   |
                    [Rename Detection] (opt-in, --detect-renames)
                                   |
                       [Topological Sort]
                        (FK dependency order)
                                   |
                        [SQL Generator]
                     (Jinja2 SandboxedEnv)
                           /          \
                     [UP block]    [DOWN block]
                           \          /
                        [.sql output]
                              |
                     [Rich Terminal Output]
```

### deltadb snapshot

```
[Live Database]
      |
  [DbLoader]
  (SQLAlchemy reflection)
      |
  [SchemaModel]
      |
  [YAML Serializer]
      |
  [schema.yml]
```

---

## 🛠️ Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| CLI | `click` 8.1+ |
| Terminal output | `rich` 13+ |
| SQL templates | `jinja2` 3.1+ (SandboxedEnvironment) |
| Database reflection | `sqlalchemy` 2.0+ |
| PostgreSQL driver | `psycopg2-binary` |
| MySQL driver | `pymysql` |
| YAML parsing | `pyyaml` 6+ (safe_load only) |
| Test runner | `pytest` 7.4+ |
| Integration tests | `testcontainers` (real PostgreSQL + MySQL) |
| Static analysis | `bandit`, `pip-audit` |
| Formatter | `black` |
| Linter | `ruff` |
| Containerization | Docker + Docker Compose |

---

## 🔒 Security

deltadb treats every input as hostile. Nine independent layers of defense, each annotated with `# [SECURITY]` in the source.

### Layer 1 — YAML Deserialization Safety

`yaml.safe_load()` exclusively. `yaml.load()` is prohibited and detected by `bandit`. Files are validated against an allowlist of root keys (`tables`, `dialect`) and rejected if they exceed 10 MB or contain unexpected structure.

```python
# [SECURITY] yaml.safe_load ONLY — yaml.load() executes arbitrary Python code
data = yaml.safe_load(f)
```

### Layer 2 — SQL Identifier Injection Prevention

Table and column names from external databases are untrusted input. Names are validated against an allowlist regex (`[a-zA-Z_][a-zA-Z0-9_]*`) and a blocklist of dangerous patterns (`;`, `--`, `/*`, `\n`, `\x00`, `xp_` prefix).

```python
# [SECURITY] Allowlist approach — only explicitly allowed characters pass
VALID_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
```

All SQL identifiers in generated output are wrapped with `quote_identifier()`, which applies dialect-appropriate quoting:

| Dialect | Quoting |
|---|---|
| PostgreSQL | `"table_name"` |
| MySQL | `` `table_name` `` |
| SQLite | `"table_name"` |

### Layer 3 — Jinja2 Template Safety

Templates run inside a `SandboxedEnvironment` that blocks access to Python internals. All interpolated values pass through security filters registered on the environment:

| Filter | Purpose |
|---|---|
| `quote_id` | Identifier validation + dialect quoting |
| `validate_type` | Column type allowlist |
| `safe_default` | Reject SQL metacharacters in DEFAULT values |
| `safe_on_action` | FK action allowlist (CASCADE, SET NULL, ...) |

Templates are static files bundled with the package. User-supplied template paths are never accepted.

### Layer 4 — Credential Security

Hierarchy: **Docker Secrets (files) > env vars > CLI arg (last resort)**.

`mask_url()` is applied before any log entry, error message, or terminal output. The masking algorithm uses `rfind("@")` to correctly handle passwords containing `@`, `#`, `?`, and other special characters.

```python
# [SECURITY] Credential masking — handles passwords with special chars (@, #, ?)
mask_url("postgresql://admin:S3cr3t!@host/db")
# → "postgresql://admin:****@host/db"
```

Connection strings are never written to: logs, generated SQL, diff output, or error messages. Raw SQLAlchemy exceptions (which may embed the URL) are caught at the loader boundary and replaced with a safe message.

### Layer 5 — Path Traversal Prevention

Output paths are resolved with `Path.resolve()` and checked for `..` components. Only `.sql`, `.json`, `.yml`, and `.yaml` extensions are accepted.

```python
# [SECURITY] Path traversal prevention — allowlist extensions
validate_output_path("../../etc/cron.d/evil.sql")  # → SecurityError
validate_output_path("output.sh")                  # → SecurityError
```

### Layer 6 — Connection String Validation

Scheme allowlist: `postgresql`, `mysql`, `sqlite`. Any other scheme raises `SecurityError` before a connection is attempted. Connection timeout is enforced at 10 seconds.

### Layer 7 — Docker Container Hardening

| Measure | Detail |
|---|---|
| Pinned image versions | `postgres:16.3-alpine3.20`, `mysql:8.0.37` — no `:latest` |
| Docker Secrets | Passwords via files (`POSTGRES_PASSWORD_FILE`), never env vars |
| `no-new-privileges: true` | Prevents privilege escalation inside container |
| `read_only: true` | Immutable root filesystem at runtime |
| `cap_drop: ALL` | All Linux capabilities dropped |
| localhost bind only | Ports on `127.0.0.1:XXXX:XXXX` — never `0.0.0.0` |
| Non-root user | uid 1001 in the image — `USER deltadb` |
| Multi-stage build | Minimal runtime image — dev tools never shipped |

### Layer 8 — Safe Error Handling

All exceptions from database operations are caught at the loader boundary, credentials masked, and a safe message returned to the caller. Stack traces appear only with `--verbose`.

### Layer 9 — Dependency Auditing

```bash
make security-check  # bandit -r deltadb/ -ll && pip-audit
```

Both pass with zero findings before every merge.

---

## 📦 Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Runtime |
| Docker | 24+ | Run PostgreSQL + MySQL for integration tests |
| Docker Compose | v2+ | Orchestrate database services |
| Make | any | Run Makefile targets |

### Docker platform requirements

| Platform | What to install |
|---|---|
| Linux (native) | [Docker Engine](https://docs.docker.com/engine/install/) |
| Windows (WSL2) | Docker Desktop for Windows → Settings → Resources → WSL Integration → enable your distro |
| macOS | Docker Desktop for Mac |

> **WSL2 note:** the legacy `docker-compose` binary is not available in WSL2. deltadb detects this automatically and falls back to `docker compose` (plugin form).

---

## 🚀 Getting Started

### 1. Clone and install

```bash
git clone https://github.com/devpedrois/deltadb.git
cd deltadb
make install
```

### 2. Set up database secrets

```bash
make setup-secrets
```

Generates cryptographically random 32-byte passwords in `secrets/pg_password.txt`, `secrets/mysql_password.txt`, and `secrets/mysql_root_password.txt`. These files are gitignored and never enter the image.

### 3. Start databases

```bash
make docker-up
```

Brings up PostgreSQL 16 and MySQL 8 with healthchecks. Waits until both are accepting connections.

### 4. Verify everything is up

```bash
docker compose ps
```

Both services should show `healthy`.

### 5. Run your first diff

```bash
deltadb diff tests/fixtures/schema_a.yml tests/fixtures/schema_b.yml --dialect postgresql
```

### 6. Generate a migration file

```bash
deltadb diff schema_a.yml schema_b.yml \
  --dialect postgresql \
  --output migrations/001_initial.sql
```

### 7. Snapshot a live database

```bash
deltadb snapshot "postgresql://user:pass@localhost/mydb" \
  --output snapshots/current.yml
```

---

## 🖥️ CLI Reference

### diff

```
deltadb diff SOURCE TARGET [OPTIONS]
```

Compares SOURCE schema to TARGET schema and outputs the SQL migration.

| Option | Default | Description |
|---|---|---|
| `--dialect` | auto-detected | `postgresql`, `mysql`, or `sqlite` |
| `--output FILE` | stdout | Write SQL to file (`.sql`) |
| `--json-output FILE` | — | Write diff summary as JSON (`.json`) |
| `--no-destructive` | false | Omit `DROP TABLE` and `DROP COLUMN` |
| `--detect-renames` | false | Enable rename heuristic |
| `--rename-threshold FLOAT` | `0.7` | Similarity threshold (0.0–1.0] |
| `--verbose` | false | Show stack traces on error |

**Examples:**

```bash
# YAML to YAML
deltadb diff schema_a.yml schema_b.yml

# Live DB to YAML, skip destructive ops
deltadb diff "postgresql://user:pass@localhost/db" schema_target.yml --no-destructive

# Detect renames with custom threshold
deltadb diff schema_a.yml schema_b.yml --detect-renames --rename-threshold 0.8

# Output SQL + JSON summary
deltadb diff schema_a.yml schema_b.yml \
  --output migrations/001.sql \
  --json-output reports/diff.json
```

### snapshot

```
deltadb snapshot SOURCE [OPTIONS]
```

Reflects a live database schema and writes it as a YAML file.

| Option | Default | Description |
|---|---|---|
| `--output FILE` | stdout | Write YAML to file (`.yml` or `.yaml`) |

**Examples:**

```bash
deltadb snapshot "postgresql://user:pass@localhost/db" --output snapshots/pg.yml
deltadb snapshot "mysql://user:pass@localhost/db"      --output snapshots/mysql.yml
```

---

## 📄 YAML Schema Format

```yaml
dialect: postgresql        # postgresql | mysql | sqlite
tables:
  users:
    columns:
      - name: id
        type: uuid
        primary_key: true
        nullable: false
      - name: email
        type: varchar(255)
        nullable: false
      - name: created_at
        type: timestamp
        nullable: false
        default: "now()"
    indexes:
      - name: idx_users_email
        columns: [email]
        unique: true
    unique_constraints:
      - name: uq_users_email
        columns: [email]
  orders:
    columns:
      - name: id
        type: serial
        primary_key: true
        nullable: false
      - name: user_id
        type: uuid
        nullable: false
    foreign_keys:
      - name: fk_orders_user
        columns: [user_id]
        referred_table: users
        referred_columns: [id]
        on_delete: CASCADE
```

**Allowed root keys:** `dialect`, `tables`

**Allowed `on_delete` / `on_update` values:** `CASCADE`, `SET NULL`, `SET DEFAULT`, `RESTRICT`, `NO ACTION`

All table names, column names, index names, FK names, and unique constraint names are validated as SQL identifiers before parsing completes.

---

## 🗄️ Dialects

| Feature | PostgreSQL | MySQL | SQLite |
|---|---|---|---|
| Identifier quoting | `"name"` | `` `name` `` | `"name"` |
| `ALTER COLUMN TYPE` | `ALTER COLUMN ... TYPE` | `MODIFY COLUMN` | Not supported (comment generated) |
| `DROP COLUMN` | Full support | Full support | Not supported (comment generated) |
| `RENAME TABLE` | `ALTER TABLE ... RENAME TO` | `RENAME TABLE` | `ALTER TABLE ... RENAME TO` |
| `RENAME COLUMN` | `ALTER TABLE ... RENAME COLUMN` | `ALTER TABLE ... RENAME COLUMN` | `ALTER TABLE ... RENAME COLUMN` |
| Foreign keys | Full support | Full support | Partial (no `ALTER TABLE ADD FK`) |

SQLite limitations are rendered as comments in the migration with a `-- NOT SUPPORTED IN SQLITE:` prefix so the file remains executable without errors.

---

## 🛡️ Safety Features

### Destructive operation markers

Every `DROP TABLE` or `DROP COLUMN` in the generated SQL is preceded by:

```sql
-- WARNING: DESTRUCTIVE operation
DROP TABLE "orders";
```

### --no-destructive flag

Omit all destructive operations from the generated migration. Useful for applying schema additions safely in a first pass:

```bash
# Phase 1: add new tables and columns only
deltadb diff schema_a.yml schema_b.yml --no-destructive --output phase1.sql

# Phase 2: after verifying, generate and review the drops separately
deltadb diff schema_a.yml schema_b.yml --output phase2_full.sql
```

### Rename detection

Pass `--detect-renames` to enable heuristic rename detection using `difflib.SequenceMatcher`. A column or table is considered renamed when its similarity score meets `--rename-threshold` (default `0.7`) and no other candidate scores higher (1:1 matching).

Detected renames generate `RENAME TABLE` / `RENAME COLUMN` statements instead of `DROP + ADD` pairs — preserving data rather than destroying it.

Without `--detect-renames`, behavior is unchanged: removed names produce `DROP`, added names produce `ADD`.

### Topological ordering

The migration generator builds a dependency graph from foreign keys and applies topological sort:

- **UP block**: tables with no FK dependencies first; dependents after
- **DOWN block**: reverse order — dependents dropped before the tables they reference

This guarantees the generated SQL executes without FK constraint violations.

---

## 🧪 Testing

### Unit tests

```bash
make test-unit
# pytest -m "not integration" -v
```

No Docker required. Covers: model, YAML loader, diff engine, rename detection, SQL generator, security (30 adversarial tests), CLI.

### Integration tests

```bash
make docker-test
# docker-up → pytest -m integration → docker-down
```

Uses `testcontainers` to spin up real PostgreSQL and MySQL instances. Tests SQLAlchemy reflection, type normalization, and FK handling against actual engines.

### Docker security tests

```bash
pytest -m docker_security
```

Verifies running containers: `docker-compose config` validity, no plaintext password in `docker inspect`, containers not running as root. Skipped automatically when Docker is not available.

### Coverage report

```bash
make test
# Generates coverage report — current: 93%
```

### Security checks

```bash
make security-check
# bandit -r deltadb/ -ll  (zero findings)
# pip-audit               (zero CVEs)
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DELTADB_SOURCE_URL` | — | Source connection string (alternative to CLI arg) |
| `DELTADB_TARGET_URL` | — | Target connection string (alternative to CLI arg) |
| `DELTADB_PG_PASSWORD_FILE` | — | Path to Docker Secret file for PostgreSQL password |
| `DELTADB_MYSQL_PASSWORD_FILE` | — | Path to Docker Secret file for MySQL password |
| `DELTADB_LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

Connection strings in env vars follow the same allowlist and masking rules as CLI args. Passwords in Docker Secret files (via `*_FILE` vars) take precedence over the connection string.

---

## 📁 Project Structure

```
deltadb/
├── deltadb/
│   ├── cli.py                   # Click commands: diff, snapshot
│   ├── config.py                # Constants: timeouts, limits, dialects
│   ├── exceptions.py            # DeltaDbError, LoaderError, SecurityError, GeneratorError
│   │
│   ├── model/                   # Frozen dataclasses — immutable schema representation
│   │   ├── column.py            # Column
│   │   ├── table.py             # Table
│   │   ├── constraint.py        # PrimaryKey, ForeignKey, UniqueConstraint
│   │   ├── index.py             # Index
│   │   ├── schema.py            # SchemaModel
│   │   └── types.py             # normalize_type(raw, dialect) → str
│   │
│   ├── loader/                  # Schema loading from DB or YAML
│   │   ├── base.py              # BaseLoader(ABC)
│   │   ├── yaml_loader.py       # YamlLoader — uses safe_load_yaml()
│   │   ├── db_loader.py         # DbLoader — SQLAlchemy reflection + identifier validation
│   │   └── factory.py           # create_loader(source) → BaseLoader
│   │
│   ├── diff/                    # Schema comparison — pure functions, no I/O
│   │   ├── changes.py           # ChangeType enum + Change dataclass
│   │   ├── comparators.py       # Per-object comparators (columns, indexes, FKs, UCs)
│   │   ├── engine.py            # DiffEngine.diff(source, target) → list[Change]
│   │   └── rename.py            # RenameDetector — SequenceMatcher heuristic
│   │
│   ├── generator/               # Changes → SQL
│   │   ├── dialects.py          # Dialect enum + detect_dialect()
│   │   ├── sql_generator.py     # SqlGenerator — SandboxedEnvironment + security filters
│   │   ├── topological.py       # topological_sort_up / topological_sort_down
│   │   └── templates/           # Jinja2 templates per dialect
│   │       ├── postgresql/      # 14 templates (.sql.j2)
│   │       ├── mysql/           # 14 templates
│   │       └── sqlite/          # 14 templates (unsupported ops rendered as comments)
│   │
│   ├── output/                  # Writing results
│   │   ├── rich_printer.py      # Colored terminal diff summary
│   │   ├── sql_writer.py        # write_sql() — validates output path before writing
│   │   └── json_writer.py       # write_json() — diff summary as JSON
│   │
│   └── security/                # Defense-in-depth security primitives
│       ├── credentials.py       # mask_url(), get_credential() (Docker Secrets > env vars)
│       ├── identifiers.py       # validate_identifier(), quote_identifier(), validate_column_type()
│       ├── path_safety.py       # validate_output_path() — no .. , allowlist extensions
│       └── yaml_safety.py       # safe_load_yaml() — size check + structure validation
│
├── tests/
│   ├── conftest.py              # pg_url / mysql_url fixtures via testcontainers
│   ├── test_security.py         # 30 adversarial tests — injection, YAML, credentials, paths
│   ├── test_docker_security.py  # Container hardening verification (skipif Docker unavailable)
│   ├── test_cli.py              # End-to-end CLI tests with CliRunner
│   ├── test_diff_engine.py      # Diff engine scenarios
│   ├── test_sql_generator.py    # SQL generation per dialect
│   ├── test_rename.py           # Rename detection
│   ├── test_db_loader.py        # DbLoader (SQLite unit + PG/MySQL integration)
│   └── fixtures/
│       ├── schema_a.yml         # Source schema fixture
│       ├── schema_b.yml         # Target schema fixture (with FKs, indexes)
│       └── malicious_schema.yml # !!python/object exploit attempt — must be rejected
│
├── secrets/                     # Docker Secrets — real values never committed
│   ├── .gitignore               # Ignores *.txt
│   └── *.txt.example            # Placeholder files showing expected format
│
├── docker-compose.yml           # Dev: PostgreSQL 16 + MySQL 8 with full hardening
├── docker-compose.test.yml      # Test override: tmpfs, no ports, ephemeral
├── Dockerfile                   # Multi-stage build, non-root user, read-only filesystem
├── Makefile                     # install, test, lint, format, security-check, docker-*
├── pyproject.toml               # Project metadata, pytest markers, ruff/black config
└── .env.example                 # Example environment variables
```

---

## 🧠 Design Decisions

**Frozen dataclasses for SchemaModel** — All model objects (`Column`, `Table`, `SchemaModel`, etc.) use `frozen=True`. The diff engine takes two immutable schemas and produces a list of `Change` objects. There is no mutation, no in-place patching. This makes the diff logic pure and trivially testable.

**Zero Trust on reflected names** — When `DbLoader` reflects a real database, every table name, column name, index name, and FK name passes through `validate_identifier()` before entering `SchemaModel`. A compromised or adversarially-named database cannot inject SQL identifiers into the generated migration.

**Jinja2 SandboxedEnvironment with filters** — Security-sensitive operations (identifier quoting, type validation, FK action validation) are implemented as Jinja2 filters registered on the environment. Templates never call Python functions directly. A template author cannot bypass security by writing `{{ table.__class__ }}` or accessing builtins.

**mask_url with rfind** — Passwords containing `@` confuse `urlparse` because `@` is the authority delimiter. The implementation uses `rfind("@")` on the raw authority section — the last `@` before the path is the correct delimiter. This correctly masks `mysql://root:p@ss#w0rd@host/db`.

**Topological sort for FK safety** — The generator builds a directed graph where an edge `A → B` means "table A has a FK referencing table B". `topological_sort_up` produces a linear order where B always appears before A (creates before dependents). `topological_sort_down` reverses this — dependents dropped first, then referenced tables.

**Rename detection as opt-in** — Rename detection changes semantics: a detected rename generates `RENAME COLUMN` (data-preserving) instead of `DROP COLUMN + ADD COLUMN` (data-destroying). Since false positives would silently corrupt data, it is opt-in with a configurable similarity threshold.

**Docker Secrets over env vars** — Passwords stored in env vars appear in `docker inspect`, `/proc/<pid>/environ`, and `ps aux`. Docker Secrets mount as files in `/run/secrets/` with `0400` permissions, readable only by the container process. `get_credential()` checks the `*_FILE` env var path first.

---

## 🤝 Contributing

1. Fork the repo and create your branch from `main`
2. Follow the branch naming convention: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`
3. Follow Conventional Commits: `feat(scope): description`, `fix(scope): description`
4. Write or update tests for any changed code — run `make test` before opening a PR
5. Run `make security-check` — `bandit` and `pip-audit` must pass
6. Open a pull request against `main`

**Accepted commit types:** `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
