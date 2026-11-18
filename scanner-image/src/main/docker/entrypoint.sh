#!/bin/sh
# The scanner image's entrypoint. It scans only where nothing can reach out or be changed: no network but loopback,
# the built artifacts read from /in, the graphs written to /out, as the owner of /out rather than root, and within
# AUTHTRACER_TIMEOUT. Exit codes: 0 every artifact scanned; 2 the container isn't run as it must be (see below);
# 3 an artifact couldn't be scanned (the others were), or the heap ran out; 124 the scan timed out; 137 it was killed,
# most likely for going over the container's memory.
set -eu

run_like_this() {
  cat >&2 <<'EOF'

Run the scanner with no network, the built jars and wars read-only at /in, and a directory for the graphs at /out:

  docker run --rm --network none --read-only --tmpfs /tmp:size=2g --cap-drop ALL \
    --security-opt no-new-privileges --memory 4g --user "$(id -u):$(id -g)" \
    -v "$PWD/build/libs:/in:ro" -v "$PWD/build/authtracer:/out" authtracer-scanner

Create the /out directory first, so the graphs are yours. scripts/scan-artifacts.sh in AuthTracer runs it this way.
EOF
}

fail() {
  echo "authtracer-scanner: $1" >&2
  run_like_this
  exit 2
}

# No network: any interface but loopback that is up can reach out of the container. Every network namespace has the
# kernel's fallback tunnels (tunl0, sit0, gre0...), down, and without NET_ADMIN nothing here can bring them up.
for interface in /sys/class/net/*; do
  name=$(basename "$interface")
  [ -d "$interface" ] && [ "$name" != lo ] || continue
  # IFF_UP, the lowest bit of the interface's flags.
  if [ $(($(cat "$interface/flags") & 1)) != 0 ]; then
    fail "the container has a network ($name), and the scanner runs only without one: add --network none."
  fi
done

[ -d /in ] || fail "nothing is mounted at /in: mount the directory with the built jars and wars there, read-only."
# An unmounted /out is the container's own, and the graphs would go with it.
mountpoint -q /out || fail "nothing is mounted at /out, so the graphs would be lost with the container."

# Not as root (GitHub's Docker actions run as root): as whoever owns /out, so the graphs are theirs.
if [ "$(id -u)" = 0 ]; then
  owner=$(stat -c %u /out)
  group=$(stat -c %g /out)
  if [ "$owner" != 0 ]; then
    if setpriv --reuid="$owner" --regid="$group" --clear-groups -- true 2> /dev/null; then
      exec setpriv --reuid="$owner" --regid="$group" --clear-groups -- "$0" "$@"
    fi
    fail "running as root without the capability to become /out's owner ($owner): add --user $owner:$group."
  fi
  echo "authtracer-scanner: running as root, and /out belongs to root, so the graphs will too, unless root here is" \
    "you (rootless Docker or Podman, Docker Desktop)." >&2
fi

[ -w /out ] || fail "user $(id -u) can't write to /out: run as its owner, with --user."
tmp=${TMPDIR:-/tmp}
[ -w "$tmp" ] || fail "$tmp isn't writable, and the artifacts are unpacked there: add --tmpfs /tmp:size=2g."

export HOME="$tmp"
limit=${AUTHTRACER_TIMEOUT:-15m}
# The heap leaves room for what is unpacked into a tmpfs, which counts against the container's memory too.
set +e
# shellcheck disable=SC2086 # JAVA_OPTS holds several options.
timeout --kill-after=30s "$limit" java -XX:MaxRAMPercentage=60 -XX:+ExitOnOutOfMemoryError -XX:-UsePerfData \
  -Djava.io.tmpdir="$tmp" ${JAVA_OPTS-} -cp '/opt/authtracer/lib/*' dev.crain.authtracer.image.ScanArtifacts &
scan=$!
# As PID 1, the shell would ignore docker stop's SIGTERM; pass it on.
trap 'kill -TERM "$scan" 2> /dev/null' TERM INT
wait "$scan"
status=$?
# A signal interrupts wait before the scan has finished: wait for its own status.
while kill -0 "$scan" 2> /dev/null; do
  wait "$scan"
  status=$?
done
set -e
if [ "$status" = 124 ]; then
  echo "authtracer-scanner: the scan took longer than $limit and was stopped; set AUTHTRACER_TIMEOUT (e.g. 30m) to" \
    "allow longer." >&2
elif [ "$status" = 137 ]; then
  echo "authtracer-scanner: the scan was killed, most likely for going over the container's memory; give it more" \
    "with --memory." >&2
fi
exit "$status"
