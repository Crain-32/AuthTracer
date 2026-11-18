#!/usr/bin/env bash
# Drives the example services as alice, bob, carol and admin, and prints one line per call: who, what, HTTP status, and
# the start of the response body. Needs identity-service (9000), employee-service (8082), profile-service (8081),
# payroll-service (8083) and their brokers running.
#
# Between the services, the calls go over every kind of link the example system has: profiles over GraphQL and
# compensation over REST (profile-service to employee-service), teams and payroll over gRPC (payroll-service to
# employee-service), salary changes over Kafka (employee-service to payroll-service's /payroll/changes, whose listener
# reads the employee's name back over gRPC with payroll-service's own token from identity-service) and compensation
# views over RabbitMQ (profile-service to employee-service's /audit/employees/{id}/views).
set -euo pipefail

SERVICE_A=${SERVICE_A:-http://localhost:8081}
SERVICE_B=${SERVICE_B:-http://localhost:8082}
SERVICE_D=${SERVICE_D:-http://localhost:8083}
HERE=$(cd "$(dirname "$0")" && pwd)

call() {
  local user=$1 token=$2 method=$3 url=$4 body=${5:-}
  local out status
  out=$(mktemp)
  if [ -n "$body" ]; then
    status=$(curl -s -o "$out" -w '%{http_code}' -X "$method" -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' -d "$body" "$url")
  else
    status=$(curl -s -o "$out" -w '%{http_code}' -X "$method" -H "Authorization: Bearer $token" "$url")
  fi
  printf '%-6s %-4s %-42s %s  %s\n' "$user" "$method" "${url#http://localhost:}" "$status" "$(head -c 150 "$out")"
  rm -f "$out"
}

for user in alice bob carol admin; do
  token=$("$HERE/token.sh" "$user")
  call "$user" "$token" GET "$SERVICE_A/profiles/1"
  call "$user" "$token" GET "$SERVICE_A/profiles"
  call "$user" "$token" GET "$SERVICE_A/admin/compensation/1"
  call "$user" "$token" GET "$SERVICE_B/employees/2"
  call "$user" "$token" POST "$SERVICE_B/graphql" '{"query": "{ employee(id: 2) { email ssn salary } }"}'
  call "$user" "$token" GET "$SERVICE_B/audit/employees/1"
  call "$user" "$token" PUT "$SERVICE_B/admin/employees/1/salary" '{"salary": 85000}'
  call "$user" "$token" GET "$SERVICE_D/teams/1"
  call "$user" "$token" GET "$SERVICE_D/teams/1/payroll"
  call "$user" "$token" GET "$SERVICE_D/directory/teams"
  call "$user" "$token" POST "$SERVICE_D/teams/2/members/1"
done

# What the brokers delivered: the admin's compensation views and salary change, a moment after they were sent.
sleep 2
for user in alice bob carol admin; do
  token=$("$HERE/token.sh" "$user")
  call "$user" "$token" GET "$SERVICE_B/audit/employees/1/views"
  call "$user" "$token" GET "$SERVICE_D/payroll/changes"
done
