#!/bin/sh
# Scans the built Spring Boot jars and wars in a directory into authorization graphs, one <service>.json each, in the
# scanner image (./gradlew :scanner-image:dockerImage builds it): with no network, a read-only file system, no
# capabilities, as you, within a memory and a time limit.
#
#   scripts/scan-artifacts.sh <dir with the built jars and wars> <dir for the graphs> [image]
#
# Passed into the container when they're set: AUTHTRACER_REVISION (else GITHUB_SHA, else what the artifact records),
# AUTHTRACER_SERVICE (with one artifact), AUTHTRACER_TIMEOUT (15m) and the facts files AUTHTRACER_FACTS and
# AUTHTRACER_ORG_FACTS, mounted read-only. AUTHTRACER_MEMORY (4g) is the container's memory. Exits with the scanner's
# code: 0 scanned; 2 run wrongly; 3 an artifact couldn't be scanned; 124 timed out; 137 out of memory.
set -eu

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "Usage: $0 <dir with the built jars and wars> <dir for the graphs> [image, authtracer-scanner:latest]" >&2
  exit 2
fi
in=$(cd "$1" && pwd)
# Made here, so it's yours: the scanner writes as the directory's owner.
mkdir -p "$2"
out=$(cd "$2" && pwd)
image=${3:-authtracer-scanner:latest}

# A facts file the environment names, mounted read-only and named inside the container.
set --
for facts in AUTHTRACER_FACTS AUTHTRACER_ORG_FACTS; do
  file=$(printenv "$facts" || true)
  if [ -n "$file" ]; then
    [ -f "$file" ] || { echo "$facts names $file, which isn't a file." >&2; exit 2; }
    path="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
    set -- "$@" -v "$path:/facts/$facts.yaml:ro" -e "$facts=/facts/$facts.yaml"
  fi
done

exec docker run --rm --network none --read-only --tmpfs /tmp:size=2g --cap-drop ALL \
  --security-opt no-new-privileges --memory "${AUTHTRACER_MEMORY:-4g}" --user "$(id -u):$(id -g)" \
  -e AUTHTRACER_REVISION -e AUTHTRACER_SERVICE -e AUTHTRACER_TIMEOUT -e GITHUB_SHA "$@" \
  -v "$in:/in:ro" -v "$out:/out" "$image"
