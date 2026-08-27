#!/bin/bash

echo "starting pgweb container"

export AWS_REGION=eu-west-2
export PGHOST=$(/usr/local/bin/aws-rds-token -service $SERVICE -host)
export PGPORT="${PGPORT:=5432}"
export PGUSER="${PGUSER:=$(echo "$SERVICE" | tr '-' '_')}"
export PGPASSWORD=$(/usr/local/bin/aws-rds-token -service $SERVICE -user $PGUSER)
export PGDATABASE="${PGDATABASE:=$(echo "$SERVICE" | tr '-' '_')}"
export PGSSLMODE="${PGSSLMODE:=require}"

echo "${PGUSER}@${PG_HOST}:${PGPORT}/${PGDATABASE}"

/usr/bin/pgweb -s --prefix="$TOKEN" --log-format=json --host="$PGHOST" --port="$PGPORT" --user="$PGUSER" --pass="$PGPASSWORD" --db="$PGDATABASE" --listen="$PORT" --bind=0.0.0.0 --no-idle-timeout --cors
