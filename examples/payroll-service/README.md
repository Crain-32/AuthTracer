# payroll-service: Teams (reactive)

Example service for AuthTracer. The reactive (Spring WebFlux) one: the same kind of authorization as profile-service and employee-service, written with the reactive stack, so AuthTracer's WebFlux support has a real service to scan, link and trace.

## Why it exists

| Pattern | Where |
|---|---|
| `SecurityWebFilterChain` with `authorizeExchange` (`pathMatchers`, `hasRole`, `hasAuthority`, an HTTP method matcher) | `security/SecurityConfig` |
| OAuth2 Resource Server, reactive JWT (`ReactiveJwtAuthenticationConverterAdapter`). Authorities from `scope` + `roles` claims (Snapshot freshness) | `security/SecurityConfig` |
| `@EnableReactiveMethodSecurity`: `@PreAuthorize` on `Mono` methods, `@PostFilter` on a `Flux` | `team/TeamService`, `payroll/PayrollLedger` |
| gRPC client: an async stub of employee-service's directory, the reply mapped into a DTO | `employeeservice/EmployeeServiceClient`, `src/main/proto` |
| Bearer token relay to employee-service: the caller's token read from the Reactor context into Spring gRPC's `BearerTokenAuthenticationInterceptor` | `employeeservice/EmployeeServiceClient` |
| Kafka: employee-service's salary changes consumed from `employee.salary-changed`, with no caller | `payroll/SalaryChangeListener` |
| Service credentials: with no caller, the listener reads the employee's name from employee-service with payroll-service's own token (OAuth2 client registration `payroll-service`, client credentials, `employees.read` only, through `AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager`). The token has no roles, so employee-service leaves the salary out | `payroll/SalaryChangeListener`, `employeeservice/EmployeeServiceClient#employeeAsPayroll`, `security/SecurityConfig` |
| Functional endpoint (`RouterFunction`) next to an annotated controller | `directory/DirectoryRoutes`, `team/TeamController` |
| A field computed from a field employee-service guards: `PayrollView.total` from `salary` | `team/TeamService` |

Fields relative to employee-service's gRPC `EmployeeRecord`:

| Field | FieldSource | From |
|---|---|---|
| `TeamView.leadName` | Computed | `first_name`, `last_name` |
| `TeamView.leadEmail` | Direct | `email` |
| `PayrollView.total` | Computed | `salary` of every member |
| `PayrollChange.employeeName` | Computed | `first_name`, `last_name`, read with payroll-service's own token |

payroll-service's own rule for `/teams/*/payroll` asks for `ROLE_ADMIN` only. `total` inherits employee-service's checks on `salary` too (its gRPC rule's and `@PreAuthorize`'s read scope and the ADMIN-or-AUDITOR field check), which is what AuthTracer's exposures show. `employeeName` doesn't: employee-service's checks on that call evaluate payroll-service, not whoever reads `/payroll/changes`.

## Endpoints
AuthTracer's [tutorial](../../guide/tutorial.md) walks through the example system. Port 8083.

## Running
Needs identity-service (9000; it issues payroll-service's own tokens at `/oauth2/token` too), employee-service (8082,
gRPC on 9082) and Kafka (9092; AuthTracer's `scripts/brokers.compose.yaml` runs it). Traces go to Zipkin on port 9411.

```
./gradlew bootRun
```

Built with the JDK 25 toolchain and `options.release = 21`. `src/main/proto/employee_directory.proto` is a copy of
employee-service's.
