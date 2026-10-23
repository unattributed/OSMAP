"""Sanitized parser for the fixed read-only stock-schema observation."""
import re


class StockSchemaRefused(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise StockSchemaRefused(code)


_MARIADB_VERSION = re.compile(
    r'(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9._]+)*)-MariaDB\Z')


def stock_fresh_reserved_schema(raw):
    """Return bounded non-secret evidence or one precise refusal code."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 4096,
        'stock_schema_output_bound')
    try:
        rows = raw.decode('ascii').splitlines()
    except UnicodeDecodeError:
        raise StockSchemaRefused('stock_schema_non_ascii') from None
    require(len(rows) == 6, 'stock_schema_row_count')
    authority = rows[0].split('\t')
    require(len(authority) == 2 and authority[0] == 'root@localhost',
        'stock_database_identity')
    version = _MARIADB_VERSION.fullmatch(authority[1])
    require(version is not None, 'stock_database_compatibility')
    require(all(re.fullmatch(r'0|[1-9][0-9]{0,9}', value) is not None
        for value in (rows[1], rows[2], rows[4], rows[5])),
        'stock_schema_numeric')
    require(rows[1] == '0', 'stock_reserved_database_user_count')
    require(rows[2] == '0', 'stock_controlled_rows_count')
    require(rows[3].casefold() == 'innodb', 'stock_mailbox_engine')
    require(rows[4] == '0', 'stock_mailbox_triggers')
    require(rows[5] == '0', 'stock_mailbox_foreign_keys')
    return {
        'database_identity': authority[0],
        'database_product': 'MariaDB',
        'database_version': version.group('version'),
        'reserved_database_users': 0,
        'controlled_rows': 0,
        'mailbox_engine': 'InnoDB',
        'mailbox_triggers': 0,
        'mailbox_foreign_keys': 0,
    }
