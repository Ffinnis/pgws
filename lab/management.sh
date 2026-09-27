#!/bin/sh
set -eu
export PATH=/usr/lib/postgresql/18/bin:/usr/bin:/bin
initdb -D /tmp/management -U postgres --auth-local=trust --auth-host=reject --encoding=UTF8 --no-locale > /tmp/initdb.log
cat >> /tmp/management/postgresql.conf <<'CONF'
listen_addresses = ''
unix_socket_directories = '/tmp'
shared_buffers = '32MB'
wal_level = logical
max_replication_slots = 10
max_slot_wal_keep_size = '128MB'
CONF
pg_ctl -D /tmp/management -l /tmp/postgres.log -w start
trap 'pg_ctl -D /tmp/management -m fast -w stop' EXIT
trap 'exit 1' INT TERM
export PGWS_TEST_DATABASE_URL='host=/tmp user=postgres dbname=postgres sslmode=disable'
/tests/policyapproval.test -test.v -test.timeout=30s
/tests/control.test -test.v -test.timeout=2m
/tests/discover.test -test.v -test.timeout=1m

PGWS_LOGICAL_LAB=1 /tests/logical.test -test.v -test.timeout=2m
PGWS_LOGICAL_CLI_LAB=1 /tests/logical-cli.test -test.v -test.timeout=1m
