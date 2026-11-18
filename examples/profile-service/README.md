# profile-service: Profiles

Example service for AuthTracer. The front of the profile-service → employee-service call chain.

## Why it exists
It creates the cross-service edges and the derived fields AuthTracer has to trace:

| Pattern | Where |
|---|---|
| `authorizeHttpRequests` request matchers (`hasAuthority`, `hasRole`) | `security/SecurityConfig` |
| OAuth2 Resource Server, JWT. Authorities from `scope` + `roles` claims (Snapshot freshness) | `security/SecurityConfig` |
| GraphQL client: `HttpSyncGraphQlClient` over Boot's `RestClient.Builder`, documents in `graphql-documents/` | `employeeservice/EmployeeGraphQlClient` (profiles) |
| REST client: Boot's `RestClient.Builder` (traced client spans) | `employeeservice/EmployeeServiceClient` (compensation) |
| Bearer token relay to employee-service, on both clients | `employeeservice/BearerTokenRelayInterceptor` |
| Inbound check + downstream field check on the same data | `admin/CompensationController` |
| RabbitMQ: each compensation view sent to employee-service's audit through the default exchange | `audit/CompensationAudit` |

Derived fields in `ProfileView`, relative to employee-service's GraphQL `Employee`:

| Field | FieldSource | From |
|---|---|---|
| `employeeId` | Direct | `id` |
| `displayName` | Computed | `firstName`, `lastName` |
| `contact` | Complex | `email` (`contact.email` is Direct) |
| `salaryBand` | Computed | `salary` |
| `ssnLast4` | Computed | `ssn` (a deliberate derived-field leak) |

Identity mechanism: OAuth2 Resource Server with JWTs issued by identity-service.

## Endpoints
AuthTracer's [tutorial](../../guide/tutorial.md) walks through the example system. Port 8081.

## Running
Needs identity-service (9000), employee-service (8082) and RabbitMQ (5672; AuthTracer's `scripts/brokers.compose.yaml`
runs it). Traces go to Zipkin on port 9411.

```
./gradlew bootRun
```

Built with the JDK 25 toolchain and `options.release = 21`.
