from deltadb.diff.changes import Change, ChangeType
from deltadb.diff.comparators import (
    _check_duplicate_names,
    compare_columns,
    compare_foreign_keys,
    compare_indexes,
    compare_unique_constraints,
)
from deltadb.model.schema import SchemaModel
from deltadb.security.identifiers import (
    validate_column_type,
    validate_default,
    validate_identifier,
)


class DiffEngine:
    # [SECURITY] Independent trust boundary — validates all identifiers even
    # if loaders already did, so direct SchemaModel construction cannot bypass
    # security checks before data reaches the SQL generator.
    def _validate_schema(self, schema: SchemaModel) -> None:
        for table_name, table in schema.tables.items():
            validate_identifier(table_name)
            for col in table.columns:
                validate_identifier(col.name)
                validate_column_type(col.type)
                if col.default is not None:
                    # [SECURITY] Coerce to str — YAML loaders may store int/bool
                    # defaults without conversion, matching Column.default: str|None
                    # at runtime. validate_default expects str; TypeError otherwise.
                    validate_default(str(col.default))
            # [SECURITY] Validate PK name and columns — previously skipped,
            # allowing malicious PK names to bypass the trust boundary.
            if table.primary_key is not None:
                if table.primary_key.name:
                    validate_identifier(table.primary_key.name)
                for col_name in table.primary_key.columns:
                    validate_identifier(col_name)
            for idx in table.indexes:
                validate_identifier(idx.name)
                for col_name in idx.columns:
                    validate_identifier(col_name)
            named_fk_names = []
            for fk in table.foreign_keys:
                if fk.name:
                    validate_identifier(fk.name)
                    named_fk_names.append(fk.name)
                for col_name in fk.columns:
                    validate_identifier(col_name)
                validate_identifier(fk.referred_table)
                for col_name in fk.referred_columns:
                    validate_identifier(col_name)
            # [SECURITY] Detect duplicate FK names before dict construction in
            # comparators silently drops one. Checked here so TABLE_ADDED paths
            # (which skip comparators) are also protected.
            _check_duplicate_names(named_fk_names, "foreign key", table_name)
            named_uc_names = []
            for uc in table.unique_constraints:
                if uc.name:
                    validate_identifier(uc.name)
                    named_uc_names.append(uc.name)
                for col_name in uc.columns:
                    validate_identifier(col_name)
            _check_duplicate_names(named_uc_names, "unique constraint", table_name)

    def diff(self, source: SchemaModel, target: SchemaModel) -> list[Change]:
        self._validate_schema(source)
        self._validate_schema(target)
        changes: list[Change] = []
        source_names = set(source.tables)
        target_names = set(target.tables)

        for name in sorted(target_names - source_names):
            changes.append(Change(
                type=ChangeType.TABLE_ADDED,
                table=name,
                new_value=target.tables[name],
            ))

        for name in sorted(source_names - target_names):
            changes.append(Change(
                type=ChangeType.TABLE_DROPPED,
                table=name,
                old_value=source.tables[name],
                destructive=True,
            ))

        for name in sorted(source_names & target_names):
            src_table = source.tables[name]
            tgt_table = target.tables[name]
            changes.extend(compare_columns(name, src_table.columns, tgt_table.columns))
            changes.extend(compare_indexes(name, src_table.indexes, tgt_table.indexes))
            changes.extend(compare_foreign_keys(name, src_table.foreign_keys, tgt_table.foreign_keys))
            changes.extend(compare_unique_constraints(name, src_table.unique_constraints, tgt_table.unique_constraints))

        return changes
