#!/bin/sh
# Runs inside temporalio/admin-tools (`make dev-up` pipes it in), before the server starts.
#
# Creates the `temporal` and `temporal_visibility` databases when they are missing and brings both
# schemas to the version this release ships. Every step is a no-op on a current schema, and
# updates are forward-only: there is no downgrade, `make dev-reset` is the way back.
# Connection settings come from the SQL_* variables temporal-sql-tool reads.
set -eu

for entry in temporal:temporal temporal_visibility:visibility; do
  database=${entry%%:*}
  directory=${entry#*:}
  temporal-sql-tool --db "$database" create-database
  temporal-sql-tool --db "$database" setup-schema --version 0.0
  temporal-sql-tool --db "$database" update-schema \
    --schema-dir "/etc/temporal/schema/postgresql/v12/$directory/versioned"
done
