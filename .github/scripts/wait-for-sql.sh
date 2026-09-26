#!/usr/bin/env bash
# Wait until the docker-compose SQL Server service accepts an authenticated
# login. A listening port is not readiness: SQL Server binds 1433 before the SA
# login and databases finish initializing, so tests started too early race it
# and hit sporadic "Login failed for user 'SA'" (18456) errors.
#
# Usage: wait-for-sql.sh <compose-service> [tools|exec]
#   tools (default): run sqlcmd from a throwaway mssql-tools container on the
#                    host network; works for every image, including
#                    azure-sql-edge, which ships no in-box sqlcmd.
#   exec:            run the in-box sqlcmd via `docker compose exec` (macOS /
#                    colima, where the host network is the VM's).
set -uo pipefail

svc=${1:?usage: wait-for-sql.sh <compose-service> [tools|exec]}
mode=${2:-tools}
pw='<YourStrong@Passw0rd>'

try_login() {
  if [ "$mode" = exec ]; then
    for bin in /opt/mssql-tools18/bin/sqlcmd /opt/mssql-tools/bin/sqlcmd; do
      docker compose -f docker-compose.yml exec -T "$svc" \
        "$bin" -S localhost -U SA -P "$pw" -C -Q "SELECT 1" >/dev/null 2>&1 && return 0
    done
    return 1
  fi
  docker run --rm --network host mcr.microsoft.com/mssql-tools \
    /opt/mssql-tools/bin/sqlcmd -S localhost,1433 -U SA -P "$pw" -Q "SELECT 1" >/dev/null 2>&1
}

for _ in $(seq 1 100); do
  if try_login; then
    echo "SQL Server ready (authenticated login succeeded)"
    exit 0
  fi
  sleep 3
done
echo "SQL Server did not accept an authenticated login in time" >&2
docker compose -f docker-compose.yml logs "$svc" || true
exit 1
