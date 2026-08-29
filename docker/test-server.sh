#!/usr/bin/env bash
#
# Start a SQL Server for the test suite, with podman or docker.
#
#   ./docker/test-server.sh up      # build, start, wait until it accepts connections
#   ./docker/test-server.sh down    # stop and remove
#   ./docker/test-server.sh logs    # follow the server log
#
# Then:
#
#   export TIBERIUS_TEST_CONNECTION_STRING='server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;IntegratedSecurity=true;TrustServerCertificate=true'
#   cargo test
#
# IMAGE selects the flavour; the default works on both x86_64 and arm64.
# The full SQL Server images are x86_64 only, so on an arm64 machine
# (Apple silicon) they either refuse to run or run under emulation.

set -euo pipefail

ENGINE="${ENGINE:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"
NAME="${NAME:-tiberius-test-mssql}"
PORT="${PORT:-1433}"
IMAGE="${IMAGE:-azure-sql-edge}"
PASSWORD='<YourStrong@Passw0rd>'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-up}" in
  up)
    echo "engine: $ENGINE   image: $IMAGE   port: $PORT"
    "$ENGINE" build -q -f "$HERE/docker-$IMAGE.dockerfile" -t "$NAME:local" "$HERE"
    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
    "$ENGINE" run -d --name "$NAME" \
      -e ACCEPT_EULA=Y \
      -e "MSSQL_SA_PASSWORD=$PASSWORD" \
      -e "SA_PASSWORD=$PASSWORD" \
      -p "$PORT:1433" \
      "$NAME:local" >/dev/null

    # The port opens well before the server will answer, so poll the log
    # rather than the socket.
    #
    # The log is captured into a variable and matched there, rather than
    # piped into `grep -q`. Under `set -o pipefail`, `grep -q` exits on the
    # first match, the writer upstream dies of SIGPIPE, and the pipeline
    # reports failure even though the match succeeded — so the wait never
    # ends.
    echo -n "waiting for SQL Server"
    for _ in $(seq 1 120); do
      logs="$("$ENGINE" logs "$NAME" 2>&1 || true)"

      case "$logs" in
        *"SQL Server is now ready for client connections"*)
          echo " — ready"
          exit 0
          ;;
      esac

      running="$("$ENGINE" ps --format '{{.Names}}' || true)"
      case "$running" in
        *"$NAME"*) ;;
        *)
          echo " — container exited:"
          "$ENGINE" logs --tail 30 "$NAME" || true
          exit 1
          ;;
      esac

      echo -n .
      sleep 2
    done
    echo " — gave up; last lines:"
    "$ENGINE" logs --tail 30 "$NAME"
    exit 1
    ;;
  down)
    "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
    echo "removed $NAME"
    ;;
  logs)
    "$ENGINE" logs -f "$NAME"
    ;;
  *)
    echo "usage: $0 {up|down|logs}" >&2
    exit 2
    ;;
esac
