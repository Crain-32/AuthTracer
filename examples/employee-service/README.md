# employee-service: Employee directory

Example service for AuthTracer. The downstream end of the profile-service → employee-service and payroll-service → employee-service call chains, and the owner of the sensitive fields.

## Why it exists
It concentrates the method-level and field-level Spring Security patterns, so AuthTracer can show Requirements on individual fields, and it serves them over each kind of API the other services use:

| Pattern | Where |
|---|---|
| `authorizeHttpRequests` request matchers (`permitAll`, `hasRole`, `authenticated`) | `security/SecurityConfig` |
| OAuth2 Resource Server, JWT. Authorities from `scope` + `roles` claims (Snapshot freshness) | `security/SecurityConfig` |
| `@PreAuthorize` with `hasAuthority('SCOPE_…')` | `EmployeeService.find`, `EmployeeService.list` |
| `@AuthorizeReturnObject` + field-level `@PreAuthorize` on getters | `EmployeeService` → `Employee.getSsn`, `Employee.getSalary` |
| `@HandleAuthorizationDenied` (custom masking handler, null-returning handler) | `Employee`, `SsnMaskingHandler` |
| `@PostFilter` with `filterObject` / `authentication` | `EmployeeService.list` |
| JSR-250 `@RolesAllowed` | `EmployeeService.updateSalary` |
| `@Secured` | `AuditService.history`, `AuditService.views` |
| GraphQL (`@QueryMapping`) returning the field-checked proxies, so each selected field keeps its check | `employee/EmployeeGraphQlController`, `graphql/schema.graphqls` |
| gRPC service on its own server (port 9082), with Spring gRPC's `authorizeRequests` and JWT authentication | `directory/EmployeeDirectoryService`, `security/SecurityConfig.grpcApiSecurity`, `src/main/proto` |
| Callers with a user's token and with a service's own: payroll-service relays its users' tokens to the gRPC directory, and its Kafka listener calls it with its own client credentials token (`employees.read`, no roles), which passes the scope checks and gets no salary | `directory/EmployeeDirectoryService`, `security/SecurityConfig.grpcApiSecurity`, `Employee.getSalary` |
| Kafka: every salary change published to `employee.salary-changed` (payroll-service consumes it) | `employee/SalaryChanges` |
| RabbitMQ: profile-service's compensation views consumed from `audit.compensation-viewed`, with no caller | `audit/CompensationViewListener` |

Identity mechanism: OAuth2 Resource Server with JWTs issued by identity-service.

## Endpoints
AuthTracer's [tutorial](../../guide/tutorial.md) walks through the example system. HTTP (REST and `/graphql`) on port 8082, gRPC on 9082.

## Running
Needs identity-service on port 9000 for real tokens (tests use mock JWTs), Kafka on 9092 and RabbitMQ on 5672
(AuthTracer's `scripts/brokers.compose.yaml` runs both). Traces go to Zipkin on port 9411.

```
./gradlew bootRun
```

Built with the JDK 25 toolchain and `options.release = 17`. The gRPC classes are generated from
`src/main/proto/employee_directory.proto`; payroll-service keeps a copy of it.
