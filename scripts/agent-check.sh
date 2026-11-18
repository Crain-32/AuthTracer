#!/usr/bin/env bash
# Decision 0028: AuthTracer's PR check for a coding agent's hook. Diffs the service project against a base ref and,
# when authorization got weaker, prints what to fix to stderr and exits 2, which agent hooks (e.g. a Claude Code Stop
# hook) feed back to the agent. Usage: agent-check.sh <service project dir> [base ref, default main]
set -uo pipefail

USAGE="usage: agent-check.sh <service project dir> [base ref]"
if [ $# -lt 1 ]; then
  echo "$USAGE" >&2
  exit 1
fi
# Without set -e a failed cd leaves PROJECT empty, and an empty project is AuthTracer's own directory.
PROJECT=$(cd "$1" 2> /dev/null && pwd) || { echo "No such directory: $1 ($USAGE)" >&2; exit 1; }
BASE=${2:-main}
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPORT=$(mktemp)
trap 'rm -f "$REPORT"' EXIT

if (cd "$HERE" && ./gradlew -q authtracerDiff -PdiffProject="$PROJECT" -PbaseRef="$BASE" -PagentReport="$REPORT" \
    -Preport="$HERE/build/reports/authtracer/diff.md" > /dev/null 2>&1); then
  exit 0
fi
if [ -s "$REPORT" ]; then
  cat "$REPORT" >&2
  exit 2
fi
echo "AuthTracer could not run the diff for $PROJECT against $BASE (see ./gradlew authtracerDiff output)." >&2
exit 1
