package dev.crain.authtracer.system;

import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import tools.jackson.databind.json.JsonMapper;

/**
 * Gets user access tokens from identity-service with the authorization_code flow, without a browser
 * (the steps are in identity-service's README).
 */
final class TokenDriver {

    private static final String CLIENT = "authtracer-driver";
    private static final String SECRET = "driver-secret";
    private static final String REDIRECT = "http://127.0.0.1:8099/callback";
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\" type=\"hidden\" value=\"([^\"]*)\"");
    private static final Pattern CODE = Pattern.compile("[?&]code=([^&]*)");

    private final URI issuer;

    TokenDriver(URI issuer) {
        this.issuer = issuer;
    }

    String accessToken(String username) {
        HttpClient http = HttpClient.newBuilder().cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NEVER).build();
        try {
            URI authorize = issuer.resolve("/oauth2/authorize?response_type=code&client_id=" + CLIENT
                    + "&scope=" + encode("openid profile employees.read employees.write")
                    + "&redirect_uri=" + encode(REDIRECT) + "&state=system-test");
            send(http, HttpRequest.newBuilder(authorize).header("Accept", "text/html").GET().build());
            String login = send(http, HttpRequest.newBuilder(issuer.resolve("/login")).GET().build()).body();
            Matcher csrf = CSRF.matcher(login);
            if (!csrf.find()) {
                throw new IllegalStateException("No CSRF token on the login page");
            }
            HttpResponse<String> loggedIn = send(http, HttpRequest.newBuilder(issuer.resolve("/login"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(form(Map.of("username", username, "password", "password", "_csrf", csrf.group(1))))
                    .build());
            URI next = issuer.resolve(location(loggedIn));
            String callback = location(send(http, HttpRequest.newBuilder(next).GET().build()));
            Matcher code = CODE.matcher(callback);
            if (!code.find()) {
                throw new IllegalStateException("No authorization code in " + callback);
            }
            String basic = Base64.getEncoder().encodeToString((CLIENT + ":" + SECRET)
                    .getBytes(StandardCharsets.UTF_8));
            HttpResponse<String> token = send(http, HttpRequest.newBuilder(issuer.resolve("/oauth2/token"))
                    .header("Authorization", "Basic " + basic)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(form(Map.of("grant_type", "authorization_code", "code",
                            URLDecoderHolder.decode(code.group(1)), "redirect_uri", REDIRECT)))
                    .build());
            return JsonMapper.builder().build().readTree(token.body()).get("access_token").asString();
        }
        catch (IOException ex) {
            throw new IllegalStateException("Token request for " + username + " failed", ex);
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }

    private static HttpResponse<String> send(HttpClient http, HttpRequest request)
            throws IOException, InterruptedException {
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String location(HttpResponse<?> response) {
        return response.headers().firstValue("Location").orElseThrow(() -> new IllegalStateException(
                "Expected a redirect from " + response.uri() + ", got " + response.statusCode()));
    }

    private static HttpRequest.BodyPublisher form(Map<String, String> fields) {
        return HttpRequest.BodyPublishers.ofString(fields.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&")));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static final class URLDecoderHolder {
        static String decode(String value) {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        }
    }
}
