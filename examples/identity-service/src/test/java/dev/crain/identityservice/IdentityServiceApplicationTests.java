package dev.crain.identityservice;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Drives the real HTTP endpoints on a random port, without a browser, exactly as the
 * README describes: cookies (JSESSIONID) and the login form's CSRF token are handled by hand.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class IdentityServiceApplicationTests {

    private static final String ISSUER = "http://localhost:9000";

    private static final Pattern CSRF_INPUT = Pattern.compile("<input[^>]*name=\"_csrf\"[^>]*value=\"([^\"]+)\"");

    private static final Pattern JSESSIONID = Pattern.compile("JSESSIONID=([^;]+)");

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private final JsonMapper json = JsonMapper.builder().build();

    @LocalServerPort
    int port;

    /** Auto-configured from the authorization server's JWK source: verifies signatures. */
    @Autowired
    JwtDecoder jwtDecoder;

    @Test
    void discoveryDocumentAdvertisesFixedIssuer() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(url("/.well-known/openid-configuration")).GET());

        assertThat(response.statusCode()).isEqualTo(200);
        Map<String, Object> config = parseJson(response.body());
        assertThat(config).containsEntry("issuer", ISSUER)
                .containsEntry("token_endpoint", ISSUER + "/oauth2/token")
                .containsEntry("jwks_uri", ISSUER + "/oauth2/jwks");
    }

    @Test
    void clientCredentialsTokenIsJwtWithScopesAndNoRoles(CapturedOutput output) throws Exception {
        HttpResponse<String> response = tokenRequest(Map.of(
                "grant_type", "client_credentials",
                "scope", "employees.read employees.write"));

        assertThat(response.statusCode()).isEqualTo(200);
        Map<String, Object> body = parseJson(response.body());
        assertThat(body).containsEntry("token_type", "Bearer").doesNotContainKey("refresh_token");

        String accessToken = (String) body.get("access_token");
        assertThat(accessToken.split("\\.")).hasSize(3);
        Jwt jwt = this.jwtDecoder.decode(accessToken);
        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256");
        assertThat(jwt.getIssuer()).hasToString(ISSUER);
        assertThat(jwt.getSubject()).isEqualTo("authtracer-driver");
        assertThat(jwt.getClaimAsStringList("scope")).containsExactlyInAnyOrder("employees.read", "employees.write");
        assertThat(jwt.hasClaim(RolesClaimTokenCustomizer.ROLES_CLAIM)).isFalse();
        assertThat(output).contains("Access token for client 'authtracer-driver' (grant client_credentials)");
    }

    @Test
    void payrollServiceGetsItsOwnTokenWithTheReadScopeOnly(CapturedOutput output) throws Exception {
        HttpResponse<String> response = tokenRequest(AuthorizationServerConfig.PAYROLL_CLIENT_ID,
                AuthorizationServerConfig.PAYROLL_CLIENT_SECRET, Map.of(
                        "grant_type", "client_credentials",
                        "scope", "employees.read"));

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        Jwt jwt = this.jwtDecoder.decode((String) parseJson(response.body()).get("access_token"));
        assertThat(jwt.getSubject()).isEqualTo("payroll-service");
        assertThat(jwt.getClaimAsStringList("scope")).containsExactly("employees.read");
        assertThat(jwt.hasClaim(RolesClaimTokenCustomizer.ROLES_CLAIM)).isFalse();
        assertThat(output).contains("Access token for client 'payroll-service' (grant client_credentials)");
    }

    @Test
    void payrollServiceCannotAskForMoreThanItIsRegisteredWith() throws Exception {
        HttpResponse<String> response = tokenRequest(AuthorizationServerConfig.PAYROLL_CLIENT_ID,
                AuthorizationServerConfig.PAYROLL_CLIENT_SECRET, Map.of(
                        "grant_type", "client_credentials",
                        "scope", "employees.read employees.write"));

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(parseJson(response.body())).containsEntry("error", "invalid_scope");
    }

    @Test
    void authorizationCodeFlowForAdminIssuesRolesClaim(CapturedOutput output) throws Exception {
        Map<String, Object> tokens = authorizationCodeFlow("admin", "openid profile employees.read");

        assertThat(tokens).containsKeys("access_token", "refresh_token", "id_token");
        Jwt accessToken = this.jwtDecoder.decode((String) tokens.get("access_token"));
        assertThat(accessToken.getIssuer()).hasToString(ISSUER);
        assertThat(accessToken.getSubject()).isEqualTo("admin");
        assertThat(accessToken.getClaimAsStringList("roles")).containsExactlyInAnyOrder("USER", "ADMIN");
        assertThat(accessToken.getClaimAsStringList("scope")).contains("employees.read")
                .containsExactlyInAnyOrder("openid", "profile", "employees.read");
        assertThat(output).contains("Customized access token for user 'admin'");

        // The ID token is not an access token and gets no roles claim.
        Jwt idToken = this.jwtDecoder.decode((String) tokens.get("id_token"));
        assertThat(idToken.hasClaim(RolesClaimTokenCustomizer.ROLES_CLAIM)).isFalse();

        // Refreshing keeps the user principal, so the new access token still carries roles.
        HttpResponse<String> refreshed = tokenRequest(Map.of(
                "grant_type", "refresh_token",
                "refresh_token", (String) tokens.get("refresh_token")));
        assertThat(refreshed.statusCode()).isEqualTo(200);
        Jwt refreshedToken = this.jwtDecoder.decode((String) parseJson(refreshed.body()).get("access_token"));
        assertThat(refreshedToken.getClaimAsStringList("roles")).containsExactlyInAnyOrder("USER", "ADMIN");
        assertThat(output).contains("Customized access token for user 'admin' (client 'authtracer-driver', grant refresh_token)");
    }

    @ParameterizedTest
    @CsvSource({ "alice, USER", "bob, USER", "carol, USER AUDITOR", "admin, USER ADMIN" })
    void authorizationCodeFlowIssuesContractRoles(String username, String expectedRoles) throws Exception {
        Map<String, Object> tokens = authorizationCodeFlow(username, "employees.read employees.write");

        Jwt accessToken = this.jwtDecoder.decode((String) tokens.get("access_token"));
        assertThat(accessToken.getSubject()).isEqualTo(username);
        assertThat(accessToken.getClaimAsStringList("roles"))
                .containsExactlyInAnyOrder(expectedRoles.split(" "));
        assertThat(accessToken.getClaimAsStringList("scope"))
                .containsExactlyInAnyOrder("employees.read", "employees.write");
    }

    /**
     * authorization_code without a browser:
     * GET /oauth2/authorize -> 302 /login, GET /login (CSRF), POST /login -> 302 back to
     * /oauth2/authorize?...&continue -> 302 to the redirect URI with ?code -> POST /oauth2/token.
     */
    private Map<String, Object> authorizationCodeFlow(String username, String scope) throws Exception {
        String state = "state-" + username;
        String authorizeQuery = form(orderedMap(
                "response_type", "code",
                "client_id", AuthorizationServerConfig.CLIENT_ID,
                "scope", scope,
                "redirect_uri", AuthorizationServerConfig.REDIRECT_URI,
                "state", state));

        // 1. Unauthenticated authorize request. Accept: text/html is required, otherwise the
        //    authorization server chain answers 401 instead of redirecting to the login page.
        HttpResponse<String> authorize = send(HttpRequest.newBuilder(url("/oauth2/authorize?" + authorizeQuery))
                .header("Accept", "text/html")
                .GET());
        assertThat(authorize.statusCode()).isEqualTo(302);
        URI loginPage = resolveLocation(authorize);
        assertThat(loginPage.getPath()).isEqualTo("/login");
        String session = sessionCookie(authorize, null);
        assertThat(session).as("JSESSIONID holding the saved authorize request").isNotNull();

        // 2. Login form: the CSRF token lives in the session, so send the cookie.
        HttpResponse<String> loginForm = send(HttpRequest.newBuilder(loginPage)
                .header("Cookie", "JSESSIONID=" + session)
                .GET());
        assertThat(loginForm.statusCode()).isEqualTo(200);
        Matcher csrf = CSRF_INPUT.matcher(loginForm.body());
        assertThat(csrf.find()).as("_csrf hidden input in login page").isTrue();
        session = sessionCookie(loginForm, session);

        // 3. Submit credentials. Session fixation protection issues a new JSESSIONID.
        HttpResponse<String> login = send(HttpRequest.newBuilder(url("/login"))
                .header("Cookie", "JSESSIONID=" + session)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(orderedMap(
                        "username", username,
                        "password", AuthorizationServerConfig.USER_PASSWORD,
                        "_csrf", csrf.group(1))))));
        assertThat(login.statusCode()).isEqualTo(302);
        URI resumedAuthorize = resolveLocation(login);
        assertThat(resumedAuthorize.getPath()).isEqualTo("/oauth2/authorize");
        session = sessionCookie(login, session);

        // 4. Resume the saved authorize request: no consent screen, straight to the redirect URI.
        HttpResponse<String> callback = send(HttpRequest.newBuilder(resumedAuthorize)
                .header("Cookie", "JSESSIONID=" + session)
                .GET());
        assertThat(callback.statusCode()).isEqualTo(302);
        String location = callback.headers().firstValue("Location").orElseThrow();
        assertThat(location).startsWith(AuthorizationServerConfig.REDIRECT_URI + "?");
        Map<String, String> callbackParams = queryParams(URI.create(location));
        assertThat(callbackParams).containsEntry("state", state).containsKey("code");

        // 5. Exchange the code (client_secret_basic).
        HttpResponse<String> token = tokenRequest(orderedMap(
                "grant_type", "authorization_code",
                "code", callbackParams.get("code"),
                "redirect_uri", AuthorizationServerConfig.REDIRECT_URI));
        assertThat(token.statusCode()).as(token.body()).isEqualTo(200);
        return parseJson(token.body());
    }

    private HttpResponse<String> tokenRequest(Map<String, String> params) throws Exception {
        return tokenRequest(AuthorizationServerConfig.CLIENT_ID, AuthorizationServerConfig.CLIENT_SECRET, params);
    }

    private HttpResponse<String> tokenRequest(String clientId, String clientSecret, Map<String, String> params)
            throws Exception {
        String basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        return send(HttpRequest.newBuilder(url("/oauth2/token"))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(params))));
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return this.http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI url(String pathAndQuery) {
        return URI.create("http://localhost:" + this.port + pathAndQuery);
    }

    private static URI resolveLocation(HttpResponse<?> response) {
        return response.uri().resolve(response.headers().firstValue("Location").orElseThrow());
    }

    private static String sessionCookie(HttpResponse<?> response, String current) {
        return response.headers().allValues("Set-Cookie").stream()
                .map(JSESSIONID::matcher)
                .filter(Matcher::find)
                .map(matcher -> matcher.group(1))
                .reduce((first, second) -> second)
                .orElse(current);
    }

    private static Map<String, String> orderedMap(String... keyValues) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put(keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    private static String form(Map<String, String> params) {
        return params.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static Map<String, String> queryParams(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : uri.getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            params.put(decode(parts[0]), parts.length > 1 ? decode(parts[1]) : "");
        }
        return params;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJson(String body) {
        return this.json.readValue(body, Map.class);
    }

}
