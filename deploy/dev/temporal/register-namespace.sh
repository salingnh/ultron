#!/bin/sh
# Runs inside temporalio/admin-tools (`make dev-up` pipes it in), after the server container is up.
#
# Waits until the cluster reports healthy, which is the readiness the server container's own
# port check cannot show, then registers the `default` namespace the application uses.
# TEMPORAL_ADDRESS is read by the `temporal` CLI itself.
set -eu

deadline=$(($(date +%s) + 120))
until temporal operator cluster health >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "temporal at $TEMPORAL_ADDRESS is not healthy after 120s:" >&2
    temporal operator cluster health >&2
    exit 1
  fi
  sleep 2
done

if ! temporal operator namespace describe --namespace default >/dev/null 2>&1; then
  temporal operator namespace create --namespace default --retention 24h
fi
