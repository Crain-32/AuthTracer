# identity-service: local OAuth2 Authorization Server

identity-service is the identity provider for AuthTracer's example services. It is a Spring Boot 4.1 app
running the OAuth2 Authorization Server that ships inside Spring Security 7.1. It issues the JWT
access tokens that the resource servers (profile-service on 8081, employee-service on 8082) validate against
`issuer-uri: http://localhost:9000`.

## Why it exists

- **Identity provider for profile-service, employee-service and payroll-service.** Every call into the example
  services carries a bearer token minted here, either for a user (`authorization_code`) or for a client itself
  (`client_credentials`): the driver client, or payroll-service when its Kafka listener reads employees from
  employee-service with no user behind the call.
- **Exercises the OAuth2 JWT issuance that resource servers depend on.** The resource servers'
  authorities come from the token: `SCOPE_` + each `scope` entry, plus `ROLE_` + each `roles`
  entry. AuthTracer should therefore classify their authority source as **JWT claims**, with
  **Snapshot** freshness. The roles are frozen into the token when it is issued (or refreshed).
  Changing a user's roles here has no effect on a token that was already issued until it expires.
- Everything runs locally and in memory. There is no Docker and no database. Restarting the
  service drops all issued authorizations and generates a new RSA signing key.

## Run

```bash
./gradlew bootRun     # listens on http://localhost:9000
./gradlew build       # compiles and runs the end-to-end token tests
```

Requires JDK 25 (Gradle toolchain).

Useful endpoints (all advertised in the discovery document):

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery (`issuer` = `http://localhost:9000`) |
| `GET /.well-known/oauth-authorization-server` | OAuth2 AS metadata |
| `GET /oauth2/jwks` | Public signing keys (RS256) |
| `GET /oauth2/authorize` | Authorization endpoint |
| `POST /oauth2/token` | Token endpoint |
| `GET/POST /login` | Form login (Spring Security default page) |

## Users and clients

All users have the password `password`.

| Username | Authorities | `roles` claim in access token |
|---|---|---|
| `alice` | `ROLE_USER` | `["USER"]` |
| `bob` | `ROLE_USER` | `["USER"]` |
| `carol` | `ROLE_USER`, `ROLE_AUDITOR` | `["AUDITOR","USER"]` |
| `admin` | `ROLE_USER`, `ROLE_ADMIN` | `["ADMIN","USER"]` |

The `roles` values are sorted alphabetically. Treat them as a set.

| Setting | Value |
|---|---|
| Client ID / secret | `authtracer-driver` / `driver-secret` |
| Client authentication | `client_secret_basic` (HTTP Basic on `/oauth2/token`) |
| Grant types | `authorization_code`, `refresh_token`, `client_credentials` |
| Redirect URI | `http://127.0.0.1:8099/callback` (nothing listens there; read `code` from the `Location` header) |
| Scopes | `openid`, `profile`, `employees.read`, `employees.write` |
| Consent screen | none (`requireAuthorizationConsent=false`) |
| PKCE | optional (`requireProofKey=false`; a `code_challenge` is still verified if you send one) |

payroll-service has a client of its own, for the calls it makes as itself:

| Setting | Value |
|---|---|
| Client ID / secret | `payroll-service` / `payroll-secret` |
| Client authentication | `client_secret_basic` |
| Grant types | `client_credentials` only |
| Scopes | `employees.read` only: asking for any other scope is `invalid_scope` |

Both clients are defined in Java (`AuthorizationServerConfig#registeredClientRepository`), not in properties.

## Token shape

Access tokens are RS256-signed JWTs that expire after 5 minutes (the Spring default). An access token
from the `authorization_code` or `refresh_token` grant looks like this:

```json
{
  "sub": "admin",
  "aud": "authtracer-driver",
  "iss": "http://localhost:9000",
  "scope": ["openid", "profile", "employees.read"],
  "roles": ["ADMIN", "USER"],
  "iat": 1792115935, "nbf": 1792115935, "exp": 1792116235,
  "jti": "..."
}
```

- `scope` inside the JWT is a **JSON array**. The `scope` field in the token endpoint's JSON
  response is a space-separated string. Spring's `JwtGrantedAuthoritiesConverter` accepts both forms.
- `roles` is added by `RolesClaimTokenCustomizer` (an `OAuth2TokenCustomizer<JwtEncodingContext>`).
  It goes only into access tokens issued for a user principal. It holds only `ROLE_*` authorities,
  with the prefix removed. Spring Security 7's `FACTOR_PASSWORD` authority is left out.
- `client_credentials` tokens have `sub` = the client's id (`authtracer-driver`, `payroll-service`) and **no**
  `roles` claim, so a check for a role denies them. ID tokens never get a `roles` claim.
- Each customization logs one INFO line, for example:
  `Customized access token for user 'admin' (client 'authtracer-driver', grant authorization_code): roles=[ADMIN, USER] scopes=[openid, profile, employees.read]`

## Client credentials token

```bash
curl -s -u authtracer-driver:driver-secret \
  -d grant_type=client_credentials \
  --data-urlencode 'scope=employees.read employees.write' \
  http://localhost:9000/oauth2/token
```

If you leave out `scope`, the token gets no scopes. Send the scopes you need explicitly.

payroll-service's own token, as its OAuth2 client registration asks for it:

```bash
curl -s -u payroll-service:payroll-secret \
  -d grant_type=client_credentials \
  -d scope=employees.read \
  http://localhost:9000/oauth2/token
```

## User token via authorization_code, without a browser

This flow was run as written against `./gradlew bootRun`. The test
`IdentityServiceApplicationTests#authorizationCodeFlowForAdminIssuesRolesClaim` runs the same steps with
`java.net.http.HttpClient`.

Rules for every step:

- **Do not follow redirects automatically** (no `curl -L`). Each step reads the `Location` header.
- **Keep the `JSESSIONID` cookie** across steps, and replace it whenever the server sends a new one.
  The session holds the saved authorize request and the CSRF token. After a successful login the
  session ID **changes** (session-fixation protection), so from that point on you must send the new
  value. A curl cookie jar (`-c jar -b jar`) handles this for you.
- Step 1 **must** send `Accept: text/html`. Without it, the authorization server's filter chain
  treats the caller as an API client and answers `401` instead of redirecting to `/login`.

```bash
AS=http://localhost:9000
REDIRECT=http://127.0.0.1:8099/callback
JAR=$(mktemp)
AUTHZ="$AS/oauth2/authorize?response_type=code&client_id=authtracer-driver&scope=openid%20profile%20employees.read&redirect_uri=$REDIRECT&state=xyz"

# 1. Start the authorization request.
#    -> 302 Location: http://localhost:9000/login ; Set-Cookie: JSESSIONID=...
curl -s -c "$JAR" -b "$JAR" -H 'Accept: text/html' -o /dev/null -w '%{http_code} %{redirect_url}\n' "$AUTHZ"

# 2. Fetch the login form (same session) and pull out the CSRF token from
#    <input name="_csrf" type="hidden" value="..." />
CSRF=$(curl -s -c "$JAR" -b "$JAR" "$AS/login" \
  | sed -n 's/.*name="_csrf" type="hidden" value="\([^"]*\)".*/\1/p')

# 3. Log in (form-encoded: username, password, _csrf).
#    -> 302 Location: http://localhost:9000/oauth2/authorize?...&state=xyz&continue
#       plus a NEW Set-Cookie: JSESSIONID=...
NEXT=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode username=admin \
  --data-urlencode password=password \
  --data-urlencode "_csrf=$CSRF" \
  "$AS/login")

# 4. Resume the saved authorize request with the new session. There is no consent screen.
#    -> 302 Location: http://127.0.0.1:8099/callback?code=...&state=xyz
CALLBACK=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$NEXT")
CODE=$(printf '%s' "$CALLBACK" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')

# 5. Exchange the code (client_secret_basic; redirect_uri must match step 1). No cookie needed.
#    -> 200 {"access_token":"...","refresh_token":"...","id_token":"...","scope":"openid profile employees.read","token_type":"Bearer","expires_in":299}
curl -s -u authtracer-driver:driver-secret \
  -d grant_type=authorization_code \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  "$AS/oauth2/token"
```

Notes:

- `state` is echoed back unchanged in the step 4 redirect. Check it if you care about CSRF on the
  client side.
- The `code` is single-use and short-lived (5 minutes).
- A wrong password at step 3 gives `302 Location: /login?error`, not a redirect back to `/oauth2/authorize`.
- Leave out `openid` from `scope` if you don't want an `id_token`. `refresh_token` is issued
  either way.
- To refresh, send `-d grant_type=refresh_token --data-urlencode "refresh_token=$RT"` with the same
  Basic credentials. The new access token keeps the same user and the same `roles`.
