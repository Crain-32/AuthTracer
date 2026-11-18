#!/usr/bin/env bash
# The whole example system for a demo: starts Kafka and RabbitMQ (in Docker), Zipkin, identity-service,
# employee-service, profile-service, payroll-service and the AuthTracer server (each only if it isn't already up), scans
# the four services and publishes their graphs, sends traffic as every user, links the stored graphs with the traces,
# and diffs two pull requests against employee-service (build/demo/*-diff.json, for the UI's Diff report). Then it keeps
# running: stop it (Ctrl+C, or IntelliJ's stop button) to stop what it started. Logs go to build/demo/.
#
# Gradle only builds the jars; everything then runs from copies in build/demo/jars (so a rebuild can't touch a running
# app), with no Gradle process kept for each. DEMO_JAVA_OPTS defaults to -XX:TieredStopAtLevel=1: the JIT stops at C1,
# which takes about a third of the CPU to start an app or run a scan, and is plenty for a demo's load.
#
#   scripts/demo.sh            # everything, then wait
#   scripts/demo.sh --no-wait  # seed and exit, leaving what it started running
#
# The services are looked for in examples/, or in SERVICES_DIR. Needs JDK 25 (JAVA_HOME or java on the PATH),
# Node.js 22.13+, git, curl, and Docker for the brokers (scripts/brokers.compose.yaml) unless they are already up on
# 9092 and 5672.
set -uo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
SERVICES_DIR=${SERVICES_DIR:-$HERE/examples}
LOGS="$HERE/build/demo"
JARS="$LOGS/jars"
WAIT=true
[[ ${1:-} == --no-wait ]] && WAIT=false
mkdir -p "$JARS"

JAVA=${JAVA_HOME:+$JAVA_HOME/bin/}java
read -r -a JAVA_OPTS <<<"${DEMO_JAVA_OPTS:--XX:TieredStopAtLevel=1}"
version=$("$JAVA" -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java.specification.version = //p')
if [[ -z $version || ${version%%.*} -lt 25 ]]; then
  echo "The demo needs JDK 25 or newer; $JAVA is ${version:-not found}. Set JAVA_HOME." >&2
  exit 2
fi

started=()
BROKERS=(docker compose -f "$HERE/scripts/brokers.compose.yaml")
brokers_started=()

stop_started() {
  if ((${#started[@]} + ${#brokers_started[@]})); then
    echo
    echo "Stopping what the demo started..."
  fi
  if ((${#started[@]})); then
    kill "${started[@]}" 2>/dev/null
    wait "${started[@]}" 2>/dev/null
  fi
  if ((${#brokers_started[@]} == 2)); then
    "${BROKERS[@]}" down >/dev/null 2>&1
  elif ((${#brokers_started[@]})); then
    "${BROKERS[@]}" rm -f -s "${brokers_started[@]}" >/dev/null 2>&1
  fi
}

up() {
  curl -s -o /dev/null -m 3 -f "$1"
}

# listening <port>: something accepts connections on localhost:<port>.
listening() {
  (exec 3<>"/dev/tcp/localhost/$1") 2>/dev/null
}

# start_brokers: the brokers that aren't listening yet, from the compose file, waiting until they are healthy.
start_brokers() {
  local missing=()
  listening 9092 && printf '%-17s already running\n' kafka || missing+=(kafka)
  listening 5672 && printf '%-17s already running\n' rabbitmq || missing+=(rabbitmq)
  ((${#missing[@]})) || return 0
  if ! docker info >/dev/null 2>&1; then
    echo "The brokers (${missing[*]}) run in Docker, which isn't running: start it (Docker Desktop) and try again" >&2
    exit 2
  fi
  printf '%-17s starting in Docker (log: build/demo/brokers.log) ...' "${missing[*]}"
  if ! "${BROKERS[@]}" up -d --wait "${missing[@]}" >"$LOGS/brokers.log" 2>&1; then
    echo " failed, see build/demo/brokers.log" >&2
    tail -20 "$LOGS/brokers.log" >&2
    "${BROKERS[@]}" rm -f -s "${missing[@]}" >/dev/null 2>&1
    exit 3
  fi
  brokers_started+=("${missing[@]}")
  echo " up"
}

# start <name> <directory> <health URL> <command...>: runs the command in the background unless the URL already answers,
# then waits until it does.
start() {
  local name=$1 dir=$2 health=$3
  shift 3
  if up "$health"; then
    printf '%-17s already running\n' "$name"
    return
  fi
  if [[ ! -d $dir ]]; then
    echo "$name: $dir doesn't exist (set SERVICES_DIR to the directory holding the four example services)" >&2
    exit 2
  fi
  printf '%-17s starting (log: build/demo/%s.log)' "$name" "$name"
  (cd "$dir" && exec "$@") >"$LOGS/$name.log" 2>&1 &
  local pid=$!
  started+=("$pid")
  for _ in $(seq 1 180); do
    if up "$health"; then
      echo " ... up"
      return
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo " ... failed, see build/demo/$name.log" >&2
      tail -20 "$LOGS/$name.log" >&2
      exit 3
    fi
    printf '.'
    sleep 2
  done
  echo " ... not up after 6 minutes, see build/demo/$name.log" >&2
  exit 3
}

# install <jar> <name>: a copy to run, put in place by a rename, so an app already running from the old copy keeps it.
install() {
  cp "$1" "$JARS/.$2.tmp" && mv -f "$JARS/.$2.tmp" "$JARS/$2.jar"
}

# The CLI, from AuthTracer's boot jar.
authtracer() {
  (cd "$HERE" && "$JAVA" "${JAVA_OPTS[@]}" -cp "$JARS/authtracer.jar" -Dloader.main=dev.crain.authtracer.cli.AuthTracerCli \
    org.springframework.boot.loader.launch.PropertiesLauncher "$@")
}

trap 'stop_started; exit 130' INT TERM

echo "== Building the jars (log: build/demo/build.log)"
if ! (cd "$HERE" && ./gradlew --console=plain -q -PservicesDir="$SERVICES_DIR" bootJar zipkinJar bootJarIdentityService \
    bootJarEmployeeService bootJarProfileService bootJarPayrollService) >"$LOGS/build.log" 2>&1; then
  echo "Building failed, see build/demo/build.log" >&2
  tail -20 "$LOGS/build.log" >&2
  exit 3
fi
install "$HERE/build/libs/AuthTracer-0.0.1-SNAPSHOT.jar" authtracer
install "$HERE/build/tools/zipkin.jar" zipkin
for service in identity-service employee-service profile-service payroll-service; do
  install "$SERVICES_DIR/$service/build/libs/$service-0.0.1-SNAPSHOT.jar" "$service"
done

echo "== Starting the example system"
start_brokers
start authtracer "$HERE" http://localhost:8080/ "$JAVA" "${JAVA_OPTS[@]}" -jar "$JARS/authtracer.jar"
start zipkin "$HERE" http://localhost:9411/health "$JAVA" "${JAVA_OPTS[@]}" -jar "$JARS/zipkin.jar"
start identity-service "$SERVICES_DIR/identity-service" http://localhost:9000/.well-known/openid-configuration \
  "$JAVA" "${JAVA_OPTS[@]}" -jar "$JARS/identity-service.jar"
start employee-service "$SERVICES_DIR/employee-service" http://localhost:8082/actuator/health \
  "$JAVA" "${JAVA_OPTS[@]}" -jar "$JARS/employee-service.jar"
start profile-service "$SERVICES_DIR/profile-service" http://localhost:8081/actuator/health \
  "$JAVA" "${JAVA_OPTS[@]}" -jar "$JARS/profile-service.jar"
start payroll-service "$SERVICES_DIR/payroll-service" http://localhost:8083/actuator/health \
  "$JAVA" "${JAVA_OPTS[@]}" -jar "$JARS/payroll-service.jar"

echo "== Scanning and publishing the four services"
for service in employee-service profile-service identity-service payroll-service; do
  if ! authtracer scan --project "$SERVICES_DIR/$service" --out "build/graphs/$service.json" \
      --publish http://localhost:8080 >"$LOGS/scan-$service.log" 2>&1; then
    echo "Scanning $service failed, see build/demo/scan-$service.log" >&2
    tail -20 "$LOGS/scan-$service.log" >&2
    stop_started
    exit 3
  fi
  grep -o 'Scanned .*' "$LOGS/scan-$service.log"
done

echo "== Sending traffic as alice, bob, carol and admin"
"$HERE/scripts/traffic.sh" >"$LOGS/traffic.txt" 2>&1 || echo "Some traffic failed, see build/demo/traffic.txt" >&2
echo "$(wc -l <"$LOGS/traffic.txt" | tr -d ' ') calls (build/demo/traffic.txt)"

echo "== Linking the stored graphs with the traces"
sleep 6
if ! curl -s -f -X POST http://localhost:8080/api/system/link -o "$LOGS/system.json"; then
  echo "Linking failed" >&2
  stop_started
  exit 3
fi
python3 - "$LOGS/system.json" <<'EOF' 2>/dev/null || true
import json, sys
graph = json.load(open(sys.argv[1]))
print(f"{len(graph['services'])} services, {len(graph['links'])} links, {len(graph.get('observations', []))} observed "
      f"calls, {len(graph.get('identities', []))} identities")
EOF

# The tutorial's pull-request checks (part 7), on throwaway copies of employee-service, compared with employee-service
# itself and the system just linked. A diff exits 1 when authorization got weaker, which is what these show.
echo "== Diffing two pull requests against employee-service"
experiments="$LOGS/experiments"
rm -rf "$experiments"
mkdir -p "$experiments"
copy() {
  rsync -a --exclude build --exclude .gradle --exclude .git "$SERVICES_DIR/employee-service/" "$experiments/$1/"
}
copy employee-service-weakened
perl -pi -e "s/\@PreAuthorize\(\"hasRole\('ADMIN'\)\"\)/\@PreAuthorize(\"isAuthenticated()\")/" \
  "$experiments/employee-service-weakened/src/main/java/dev/crain/employeeservice/employee/Employee.java"
copy employee-service-shortcut
mkdir -p "$experiments/employee-service-shortcut/src/main/java/dev/crain/employeeservice/directory"
cat >"$experiments/employee-service-shortcut/src/main/java/dev/crain/employeeservice/directory/DirectoryController.java" <<'EOF'
package dev.crain.employeeservice.directory;

import dev.crain.employeeservice.employee.EmployeeRepository;
import dev.crain.employeeservice.employee.EmployeeResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DirectoryController {

    private final EmployeeRepository repository;

    DirectoryController(EmployeeRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/directory/{id}")
    EmployeeResponse get(@PathVariable long id) {
        return EmployeeResponse.from(repository.findById(id).orElseThrow());
    }
}
EOF
for change in weakened shortcut; do
  rm -f "$LOGS/$change-diff.json" "$LOGS/$change-diff.md"
  authtracer diff --project "$experiments/employee-service-$change" --base-project "$SERVICES_DIR/employee-service" \
    --context "$LOGS/system.json" --json "$LOGS/$change-diff.json" --report "$LOGS/$change-diff.md" \
    >"$LOGS/diff-$change.log" 2>&1
  if [[ -f $LOGS/$change-diff.json ]]; then
    echo "$change: $(grep -o 'Result: .*' "$LOGS/$change-diff.md" | head -1)  -> build/demo/$change-diff.json"
  else
    echo "$change: the diff didn't run, see build/demo/diff-$change.log" >&2
  fi
done

echo
echo "Ready: open http://localhost:8080 and press Latest system graph."
echo "Diff reports: Open file (or drag onto the page) build/demo/shortcut-diff.json or build/demo/weakened-diff.json."
echo "The video tour is guide/video/authtracer-tour.mp4; the walkthrough is guide/tutorial.md."
if $WAIT; then
  if ((${#started[@]})); then
    echo "Stop this (Ctrl+C or the stop button) to stop what it started."
    wait
  fi
fi
