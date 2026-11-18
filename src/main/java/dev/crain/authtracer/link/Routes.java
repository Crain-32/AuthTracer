package dev.crain.authtracer.link;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Comparing route templates ({@code /employees/{id}}) with each other and with concrete paths.
 */
@Supports(Feature.SYSTEM_GRAPH)
final class Routes {

    /**
     * A SOAP operation's namespace and the SOAP action a call names (decision 0056), as conditions.
     */
    static final String NAMESPACE = "namespace:";
    static final String SOAP_ACTION = "soapAction:";

    private Routes() {
    }

    /**
     * Same template, ignoring variable names: {@code /a/{id}} equals {@code /a/{employeeId}}.
     */
    static boolean sameTemplate(String left, String right) {
        return normalize(left).equals(normalize(right));
    }

    /**
     * Whether a call to the egress template can land on the ingress route: the same template, or a route whose
     * variables stand where the call has a literal ({@code /users/me} lands on {@code /users/{id}}); for a template with
     * wildcards ({@code /employees/**}, a gateway route's), a route under it (decision 0043); for a route with wildcards
     * ({@code /eureka/**}, a servlet's, {@code /actuator/health/{*path}}), a template it matches.
     */
    static boolean reaches(String egressTemplate, String ingressRoute) {
        if (!wildcard(egressTemplate)) {
            return wildcard(ingressRoute) ? pattern(ingressRoute)
                    .map(pattern -> pattern.matches(PathContainer.parsePath(sample(egressTemplate)))).orElse(false)
                    : matchesPath(ingressRoute, egressTemplate);
        }
        return pattern(egressTemplate).map(pattern -> pattern.matches(PathContainer.parsePath(
                ingressRoute.replaceAll("\\{\\*[^}]+}", "x/y").replaceAll("\\{[^}]+}", "x")))).orElse(false);
    }

    /**
     * Decision 0044: a message sent to a topic, queue or destination reaches the listeners of that name; a Kafka
     * listener's {@code topicPattern} is a regular expression over topic names.
     */
    static boolean sameDestination(String kind, String sent, String listened) {
        if (sent.equals(listened)) {
            return true;
        }
        if (!kind.equals("KAFKA") || listened.chars().noneMatch(c -> "*+?[](){}|^$\\".indexOf(c) >= 0)) {
            return false;
        }
        try {
            return Pattern.matches(listened, sent);
        }
        catch (PatternSyntaxException e) {
            return false;
        }
    }

    /**
     * Whether a concrete path such as {@code /employees/7} fits a template.
     */
    static boolean matchesPath(String template, String path) {
        if (wildcard(template)) {
            return pattern(template).map(pattern -> pattern.matches(PathContainer.parsePath(path))).orElse(false);
        }
        String[] templateSegments = normalize(template).split("/", -1);
        String[] pathSegments = normalize(path).split("/", -1);
        if (templateSegments.length != pathSegments.length) {
            return false;
        }
        for (int i = 0; i < templateSegments.length; i++) {
            if (!templateSegments[i].equals("{}") && !templateSegments[i].equals(pathSegments[i])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Mapping conditions an Ingress's params can carry besides request parameters (see the scanner's
     * {@code RequestMappings.CONDITIONS}), and the handler that tells two Ingress with one id apart.
     */
    private static final List<String> CONDITIONS = List.of("header:", "consumes:", "produces:", "version:",
            "handler=", NAMESPACE);

    /**
     * Whether a call with this query string can reach an endpoint mapped with these params ({@code a=b},
     * {@code a}, {@code !a}, {@code a!=b}, joined with {@code &}): always, when either is unknown.
     */
    static boolean paramsMatch(String query, String params) {
        if (query == null || params == null) {
            return true;
        }
        Map<String, String> sent = new HashMap<>();
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            sent.put(equals < 0 ? pair : pair.substring(0, equals), equals < 0 ? "" : pair.substring(equals + 1));
        }
        for (String condition : params.split("&")) {
            if (CONDITIONS.stream().anyMatch(condition::startsWith)) {
                // A header, media type or API version: not in the query.
                continue;
            }
            if (condition.startsWith("!")) {
                if (sent.containsKey(condition.substring(1))) {
                    return false;
                }
            }
            else if (condition.contains("!=")) {
                String[] parts = condition.split("!=", 2);
                if (parts[1].equals(sent.get(parts[0]))) {
                    return false;
                }
            }
            else if (condition.contains("=")) {
                String[] parts = condition.split("=", 2);
                String value = sent.get(parts[0]);
                // A variable ({p1}) could be any value.
                if (value == null || !value.equals(parts[1]) && !value.startsWith("{")) {
                    return false;
                }
            }
            else if (!sent.containsKey(condition)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decision 0056: a SOAP call reaches an operation of its request's namespace, when both are known.
     */
    static boolean sameNamespace(String query, String params) {
        Optional<String> sent = condition(query, NAMESPACE);
        Optional<String> mapped = condition(params, NAMESPACE);
        return sent.isEmpty() || mapped.isEmpty() || sent.equals(mapped);
    }

    /**
     * The value of a condition a call's query or an Ingress's params carry ({@code namespace:<uri>}).
     */
    static Optional<String> condition(String conditions, String prefix) {
        return conditions == null ? Optional.empty() : Arrays.stream(conditions.split("&"))
                .filter(condition -> condition.startsWith(prefix)).map(condition -> condition.substring(
                        prefix.length())).findFirst();
    }

    /**
     * Whether an endpoint's params name a request parameter, not only conditions a query can't meet.
     */
    static boolean namesParameters(String params) {
        return params != null && Arrays.stream(params.split("&"))
                .anyMatch(condition -> CONDITIONS.stream().noneMatch(condition::startsWith));
    }

    static boolean sameMethod(String left, String right) {
        return left == null || right == null || left.equals("*") || right.equals("*")
                || left.equalsIgnoreCase(right);
    }

    /**
     * The path of a URL or path, without query string.
     */
    static String path(String url) {
        try {
            String path = URI.create(url).getRawPath();
            return path == null || path.isEmpty() ? "/" : path;
        }
        catch (IllegalArgumentException ex) {
            int query = url.indexOf('?');
            return query < 0 ? url : url.substring(0, query);
        }
    }

    static Optional<String> host(String url) {
        if (url == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(URI.create(url).getHost());
        }
        catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    static Optional<Integer> port(String url) {
        try {
            URI uri = URI.create(url);
            if (uri.getPort() > 0) {
                return Optional.of(uri.getPort());
            }
            return Optional.ofNullable(uri.getScheme()).map(scheme -> scheme.equals("https") ? 443 : 80);
        }
        catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    private static boolean wildcard(String template) {
        return template.contains("*");
    }

    /**
     * A concrete path a template stands for: each variable one segment.
     */
    private static String sample(String template) {
        String path = template.replaceAll("\\{[^}]*}", "x");
        return path.startsWith("/") ? path : "/" + path;
    }

    private static Optional<PathPattern> pattern(String template) {
        try {
            return Optional.of(PathPatternParser.defaultInstance.parse(template.startsWith("/") ? template
                    : "/" + template));
        }
        catch (IllegalArgumentException invalid) {
            return Optional.empty();
        }
    }

    private static String normalize(String route) {
        String path = route.replaceAll("\\{[^}]*}", "{}");
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path.startsWith("/") ? path : "/" + path;
    }
}
