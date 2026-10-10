import os
import sys
import psycopg
from psycopg.rows import dict_row

def main():
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise SystemExit("Set DATABASE_URL to a PostgreSQL connection string for an authorized database.")
    try:
        with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5) as conn:
            current = conn.execute("""
                SELECT current_database() AS database,
                       current_user AS role,
                       inet_server_addr()::text AS server_address
            """).fetchone()
            role = conn.execute("""
                SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication
                FROM pg_roles WHERE rolname = current_user
            """).fetchone()
            tables = conn.execute("""
                SELECT table_schema, table_name,
                       has_table_privilege(current_user,
                           quote_ident(table_schema)||'.'||quote_ident(table_name),
                           'INSERT') AS can_insert,
                       has_table_privilege(current_user,
                           quote_ident(table_schema)||'.'||quote_ident(table_name),
                           'UPDATE') AS can_update,
                       has_table_privilege(current_user,
                           quote_ident(table_schema)||'.'||quote_ident(table_name),
                           'DELETE') AS can_delete
                FROM information_schema.tables
                WHERE table_schema NOT IN ('pg_catalog','information_schema')
                  AND table_type = 'BASE TABLE'
                ORDER BY table_schema, table_name
            """).fetchall()
        print("Database audit (read-only checks)")
        print("Connection:", dict(current))
        print("Current role:", dict(role) if role else "Not found")
        if role and (role["rolsuper"] or role["rolcreaterole"] or role["rolcreatedb"]):
            print("WARNING: current role has elevated privileges; review whether required.")
        print("\nTable privileges:")
        for table in tables:
            print(dict(table))
            if table["can_delete"] or table["can_update"]:
                print("  REVIEW: role can modify records in this table.")
        print("\nThis is a limited privilege review, not a full database security audit.")
    except psycopg.Error as exc:
        raise SystemExit(f"Database audit failed: {exc}")

if __name__ == "__main__":
    main()
