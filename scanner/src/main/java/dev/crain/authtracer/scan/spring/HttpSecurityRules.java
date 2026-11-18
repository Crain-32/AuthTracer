package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.AuthorizationLocation.Scope;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.SecurityDsl.Interpretation;
import dev.crain.authtracer.scan.spring.SecurityDsl.Receiver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.server.PathContainer;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.util.pattern.PathPatternParser;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * {@code authorizeHttpRequests} rules, read from the {@code SecurityFilterChain} bean methods and the customizer beans
 * that apply to them (each interpreted by {@link SecurityDsl}). Rules keep declaration order; the first matching rule
 * decides, and a request that matches no rule is denied (Spring Security 7's
 * {@code RequestMatcherDelegatingAuthorizationManager}). Requests matched by a {@code WebSecurityCustomizer}'s
 * {@code ignoring()} skip every chain: {@code WebSecurity#performBuild} puts their empty chains first.
 */
@Supports(Feature.REQUEST_RULES)
final class HttpSecurityRules {

    private static final Logger LOG = LoggerFactory.getLogger(HttpSecurityRules.class);
    /**
     * The patterns warned about as not parsing, once each.
     */
    private static final Set<String> UNPARSED = ConcurrentHashMap.newKeySet();
    private static final String ORDER = "org.springframework.core.annotation.Order";
    private static final String BOOT_DEFAULT_CHAIN =
            "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration";
    private static final String WEB_SECURITY_CUSTOMIZER =
            "org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer";
    private static final String WEB_SECURITY = "org.springframework.security.config.annotation.web.builders.WebSecurity";
    private static final Set<String> CUSTOMIZERS = Set.of("org.springframework.security.config.Customizer",
            "org.springframework.security.config.ThrowingCustomizer");
    private static final String SERVER_HTTP_SECURITY = "org.springframework.security.config.web.server.ServerHttpSecurity";
    private static final String AUTHORIZE_EXCHANGE_SPEC = SERVER_HTTP_SECURITY + "$AuthorizeExchangeSpec";
    private static final String SERVLET_DEFAULT_CHAIN =
            "org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration";
    private static final String WEBFLUX_DEFAULT_CHAIN =
            "org.springframework.security.config.annotation.web.reactive.WebFluxSecurityConfiguration";
    private static final String BOOT_REACTIVE_SECURITY =
            "org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration";
    private static final String KOTLIN_FUNCTION_1 = "kotlin.jvm.functions.Function1";
    private static final String IGNORING = "WebSecurityCustomizer ignoring() (skips the filter chain)";
    private static final String MANAGEMENT_SECURITY =
            "org.springframework.boot.security.autoconfigure.actuate.web.servlet.ManagementWebSecurityAutoConfiguration";
    private static final String REACTIVE_MANAGEMENT_SECURITY = "org.springframework.boot.security.autoconfigure.actuate"
            + ".web.reactive.ReactiveManagementWebSecurityAutoConfiguration";
    private static final String REGISTRY = "org.springframework.security.config.annotation.web.configurers"
            + ".AuthorizeHttpRequestsConfigurer$AuthorizationManagerRequestMatcherRegistry";
    private static final String MATCHER_BUILDER_FACTORY =
            "org.springframework.security.config.web.PathPatternRequestMatcherBuilderFactoryBean";
    private static final String HTTP_SERVLET = "jakarta.servlet.http.HttpServlet";
    private static final GenericType REQUEST_MANAGER_POST_PROCESSOR = new GenericType(
            SecurityDsl.OBJECT_POST_PROCESSOR, List.of(new GenericType(
                    "org.springframework.security.authorization.AuthorizationManager",
                    List.of(new GenericType("jakarta.servlet.http.HttpServletRequest", List.of())))));
    /**
     * A request's own dispatch, and the one the error page gets.
     */
    static final String REQUEST = "REQUEST";
    private static final String ERROR = "ERROR";

    /**
     * A request matcher: it matches when any of its parts does. {@code custom} names a part that can't be evaluated
     * statically: one that may match any request (a {@code RequestMatcher} lambda, a pattern that isn't a constant),
     * or one that never matches (an {@code EndpointRequest} or {@code GrpcRequest} with nothing to match).
     */
    @Supports({Feature.CALL_PATHS, Feature.PROVIDED_FACTS})
    record Matcher(List<Part> parts, String custom) {

        static final Matcher ANY_REQUEST = paths(null, List.of("/**"));
        /**
         * Custom parts that may match a request: AuthTracer can't tell which.
         */
        private static final Set<String> UNKNOWN = Set.of("RequestMatcher", "requestMatchers(RequestMatcher...)",
                "ServerWebExchangeMatcher", "new RegexRequestMatcher(..)", "RegexRequestMatcher",
                "PathPatternRequestMatcher", "matchers(MessageMatcher)", Matcher.NOT_CONSTANT,
                "securityMatcher(RequestMatcher)", "methods(..)");
        /**
         * A pattern built at run time ({@code base + "/orders"}), which may match any request.
         */
        static final String NOT_CONSTANT = "a pattern that isn't a constant";

        /**
         * A part AuthTracer can't evaluate may match a request this matcher's own parts don't.
         */
        boolean mayMatch() {
            return custom != null && java.util.Arrays.stream(custom.split(", ")).anyMatch(UNKNOWN::contains);
        }

        /**
         * Whether the matcher may match the request without surely matching it: a part AuthTracer can't evaluate, or
         * a lambda's test the caller decides (HTTP-06).
         */
        boolean mayMatch(String method, String path) {
            return mayMatch() || parts.stream().anyMatch(part -> part.truth(method, path) == Truth.MAYBE);
        }

        /**
         * Whether a lambda's test of what the caller sends decides, not a part AuthTracer can't evaluate.
         */
        boolean callerDecides() {
            return !mayMatch() && !callerChoices().isEmpty();
        }

        /**
         * What the caller decides among the tests: the headers and parameters it sends, how it writes the URI.
         */
        List<String> callerChoices() {
            List<String> choices = new ArrayList<>(parts.stream().flatMap(part -> part.tests().stream())
                    .map(Test::choice).filter(java.util.Objects::nonNull).toList());
            // Decision 0093: an exact URL with a query string matches only when the caller sends that one.
            parts.stream().filter(part -> part.syntax() == Syntax.EXACT && part.pattern().contains("?"))
                    .map(part -> "the query string " + part.pattern().substring(part.pattern().indexOf('?'))
                            + " on " + part.pattern().substring(0, part.pattern().indexOf('?')))
                    .forEach(choices::add);
            return choices.stream().distinct().toList();
        }

        enum Truth {
            TRUE, FALSE, MAYBE;

            static Truth of(boolean known) {
                return known ? TRUE : FALSE;
            }

            Truth not() {
                return this == TRUE ? FALSE : this == FALSE ? TRUE : MAYBE;
            }
        }

        /**
         * HTTP-06: one thing a {@code RequestMatcher} lambda tests, against a constant. What the request's method and
         * servlet path say is known for a route; a header, a parameter and the raw URI (which a caller can
         * percent-encode and still reach the same handler) are the caller's to decide.
         */
        record Test(Kind kind, String value, boolean negated) {

            enum Kind {
                METHOD, PATH_PREFIX, PATH, URI_PREFIX, URI, HEADER, PARAMETER,
                /** {@code "/admin/reports".startsWith(path)}: the path is the start of the value. */
                PATH_START_OF,
                /** {@code path.equalsIgnoreCase("/ops")}. */
                PATH_IGNORING_CASE
            }

            Test not() {
                return new Test(kind, value, !negated);
            }

            Truth truth(String method, String path) {
                Truth positive = switch (kind) {
                    // A mapping for any method: the caller picks one.
                    case METHOD -> method.equals("*") ? Truth.MAYBE : method.equals(value) ? Truth.TRUE : Truth.FALSE;
                    case PATH_PREFIX -> prefix(path, value);
                    case PATH -> exact(path, value);
                    case PATH_START_OF -> literal(path) ? Truth.of(value.startsWith(path)) : Truth.MAYBE;
                    case PATH_IGNORING_CASE -> literal(path) ? Truth.of(path.equalsIgnoreCase(value)) : Truth.MAYBE;
                    case URI_PREFIX -> prefix(path, value) == Truth.FALSE ? Truth.FALSE : Truth.MAYBE;
                    case URI -> exact(path, value) == Truth.FALSE ? Truth.FALSE : Truth.MAYBE;
                    case HEADER, PARAMETER -> Truth.MAYBE;
                };
                return negated ? positive.not() : positive;
            }

            /**
             * Whether a route's requests start with the prefix: where the route has a variable or a wildcard before
             * the prefix ends, the caller's path decides.
             */
            private static Truth prefix(String route, String prefix) {
                String literal = literalPrefix(route);
                if (literal.startsWith(prefix)) {
                    return Truth.TRUE;
                }
                return literal.length() < route.length() && prefix.startsWith(literal) ? Truth.MAYBE : Truth.FALSE;
            }

            private static boolean literal(String route) {
                return literalPrefix(route).equals(route);
            }

            private static Truth exact(String route, String path) {
                if (literal(route)) {
                    return route.equals(path) ? Truth.TRUE : Truth.FALSE;
                }
                try {
                    return PathPatternParser.defaultInstance.parse(route).matches(PathContainer.parsePath(path))
                            ? Truth.MAYBE : Truth.FALSE;
                }
                catch (IllegalArgumentException invalid) {
                    return Truth.MAYBE;
                }
            }

            String describe() {
                String not = negated ? "not " : "";
                return switch (kind) {
                    case METHOD -> not + value;
                    case PATH_PREFIX -> "path " + not + "under " + value;
                    case PATH -> "path " + not + value;
                    case PATH_START_OF -> "path " + not + "a start of " + value;
                    case PATH_IGNORING_CASE -> "path " + not + value + " in any case";
                    case URI_PREFIX -> "URI " + not + "under " + value;
                    case URI -> "URI " + not + value;
                    case HEADER -> (negated ? "no " : "") + "header " + value;
                    case PARAMETER -> (negated ? "no " : "") + "parameter " + value;
                };
            }

            /**
             * What the caller decides for this test, {@code null} for the method and path a route has.
             */
            String choice() {
                return switch (kind) {
                    case HEADER -> "the header " + value;
                    case PARAMETER -> "the parameter " + value;
                    case URI_PREFIX, URI -> "how it writes the URI, which it can percent-encode and still reach the same"
                            + " handler";
                    default -> null;
                };
            }
        }

        /**
         * How a part's pattern reads the request.
         */
        enum Syntax {
            /** A {@code PathPattern}, on the request path without the context path. */
            PATH,
            /** A {@code RegexRequestMatcher} pattern, which also sees {@code ?} and the query string. */
            REGEX,
            /** Spring gRPC's {@code methods(..)}: {@code *} wildcards on the full method name (decision 0032). */
            GRPC,
            /**
             * HTTP-05: {@code dispatcherTypeMatchers(..)}, a {@code DispatcherType} name. 7.1.1's
             * {@code DispatcherTypeRequestMatcher} compares it with the request's dispatch (and its method, if given),
             * not its path: {@code REQUEST} matches every request's own dispatch.
             */
            DISPATCH,
            /** HTTP-06: a lambda's tests, all of which must hold; {@code pattern} describes them. */
            TESTS,
            /**
             * Decision 0093: {@code PermitAllSupport}'s URLs. 7.1.1's {@code ExactUrlRequestMatcher} compares the
             * request URI, with {@code ?} and the query string when there is one, with the URL exactly, whatever the
             * method: {@code /login} matches no request with a query string, {@code /login?error} only that one.
             */
            EXACT
        }

        /**
         * @param tests for {@link Syntax#TESTS}, what must all hold
         */
        record Part(String httpMethod, String pattern, Syntax syntax, List<Test> tests) {

            Part(String httpMethod, String pattern, Syntax syntax) {
                this(httpMethod, pattern, syntax, List.of());
            }

            /**
             * Whether the part matches a route's requests where {@link #matches} can't say: for
             * {@link Syntax#TESTS}, and for a part with a method on a mapping for any method, whose caller picks the
             * method; {@code FALSE} for the others.
             */
            Truth truth(String method, String path) {
                if (httpMethod != null && method.equals("*")) {
                    return new Part(null, pattern, syntax, tests).matches(method, path, "") ? Truth.MAYBE
                            : Truth.FALSE;
                }
                if (syntax == Syntax.EXACT) {
                    // The route's requests match when the caller sends the URL's query string.
                    int mark = pattern.indexOf('?');
                    return mark >= 0 && path.equals(pattern.substring(0, mark)) ? Truth.MAYBE : Truth.FALSE;
                }
                if (syntax != Syntax.TESTS) {
                    return Truth.FALSE;
                }
                List<Truth> each = tests.stream().map(test -> test.truth(method, path)).toList();
                return each.contains(Truth.FALSE) ? Truth.FALSE : each.contains(Truth.MAYBE) ? Truth.MAYBE
                        : Truth.TRUE;
            }

            boolean regex() {
                return syntax == Syntax.REGEX;
            }

            boolean matches(String method, String path, String query) {
                return matches(method, path, query, REQUEST);
            }

            /**
             * @param dispatch the request's {@code DispatcherType}; a path is the error page's on an {@code ERROR}
             *        dispatch
             */
            boolean matches(String method, String path, String query, String dispatch) {
                if (syntax == Syntax.GRPC) {
                    return method.equals(GrpcServices.GRPC) && PatternMatchUtils.simpleMatch(pattern, path);
                }
                // A mapping for any method takes the method's requests only when the caller picks it: truth(..).
                if (httpMethod != null && (method.equals("*") || !httpMethod.equals(method))) {
                    return false;
                }
                if (syntax == Syntax.DISPATCH) {
                    return pattern.equals(dispatch);
                }
                if (syntax == Syntax.EXACT) {
                    return (path + query).equals(pattern);
                }
                if (syntax == Syntax.TESTS) {
                    return truth(method, path) == Truth.TRUE;
                }
                try {
                    if (regex()) {
                        // Path variables take a few typical values; one match is enough.
                        java.util.regex.Pattern compiled = java.util.regex.Pattern.compile(pattern,
                                java.util.regex.Pattern.DOTALL);
                        return java.util.stream.Stream.of("x", "1").anyMatch(value -> compiled.matcher(
                                path.replaceAll("\\{\\*[^}]+}", value + "/" + value)
                                        .replaceAll("\\{[^}]+}", value) + query).matches());
                    }
                    String sample = path.replaceAll("\\{\\*[^}]+}", "x/y").replaceAll("\\{[^}]+}", "x");
                    return PathPatternParser.defaultInstance.parse(pattern).matches(PathContainer.parsePath(sample));
                }
                catch (IllegalArgumentException invalid) {
                    // Spring wouldn't start with it: AuthTracer read the pattern wrong, or the app doesn't run.
                    if (UNPARSED.add(pattern)) {
                        LOG.warn("The rule pattern '{}' isn't one Spring parses ({}); the rule is read as matching no"
                                + " request", pattern, invalid.getMessage());
                    }
                    return false;
                }
            }
        }

        static Matcher paths(String httpMethod, List<String> patterns) {
            return new Matcher(patterns.stream().map(pattern -> new Part(httpMethod, pattern, Syntax.PATH)).toList(),
                    null);
        }

        /**
         * Spring gRPC's {@code methods("fixtures.grpc.Greeter/*")}; {@code allRequests()} is {@code *}.
         */
        /**
         * Decision 0093: {@code PermitAllSupport}'s exact URLs.
         */
        static Matcher exactUrls(List<String> urls) {
            return new Matcher(urls.stream().map(url -> new Part(null, url, Syntax.EXACT)).toList(), null);
        }

        static Matcher grpc(List<String> patterns) {
            return new Matcher(patterns.stream().map(pattern -> new Part(null, pattern, Syntax.GRPC)).toList(), null);
        }

        static Matcher regex(String httpMethod, String pattern) {
            return new Matcher(List.of(new Part(httpMethod, pattern, Syntax.REGEX)), null);
        }

        /**
         * HTTP-06: a lambda's tests, as alternatives each of whose tests must hold; none for one that never matches.
         */
        static Matcher tests(List<List<Test>> alternatives) {
            if (alternatives.isEmpty()) {
                return custom("a RequestMatcher that matches no request");
            }
            return new Matcher(alternatives.stream().map(tests -> new Part(null, tests.isEmpty() ? "every request"
                    : String.join(" and ", tests.stream().map(Test::describe).toList()), Syntax.TESTS, tests))
                    .toList(), null);
        }

        /**
         * {@code dispatcherTypeMatchers([method,] types)}, or a {@code new DispatcherTypeRequestMatcher(..)}.
         */
        static Matcher dispatch(String httpMethod, List<String> dispatcherTypes) {
            return new Matcher(dispatcherTypes.stream().map(type -> new Part(httpMethod, type, Syntax.DISPATCH))
                    .toList(), null);
        }

        static Matcher custom(String description) {
            return new Matcher(List.of(), description);
        }

        static Matcher anyOf(List<Matcher> matchers, List<String> unknown) {
            List<Part> parts = matchers.stream().flatMap(matcher -> matcher.parts().stream()).toList();
            List<String> custom = new ArrayList<>(matchers.stream().map(Matcher::custom)
                    .filter(java.util.Objects::nonNull).toList());
            custom.addAll(unknown);
            return new Matcher(parts, custom.isEmpty() ? null : String.join(", ", custom));
        }

        /**
         * @param path the request path without the context path: the servlet path and the route
         */
        boolean matches(String method, String path) {
            return matches(method, path, REQUEST);
        }

        boolean matches(String method, String path, String dispatch) {
            return parts.stream().anyMatch(part -> part.matches(method, path, "", dispatch));
        }

        /**
         * For a route that is a pattern itself ({@code /api/**}, a gateway route or a servlet's mapping), whether a
         * path pattern of this matcher is narrower and under it ({@code /api/public/**}): it takes some of the
         * route's requests. For a route with path variables ({@code /reports/{type}}), whether a pattern this
         * matcher doesn't match the route's sample with still matches some of its paths ({@code /reports/public-*}
         * takes {@code /reports/public-q1}).
         */
        boolean within(String method, String route) {
            return within(method, route, sample -> false);
        }

        /**
         * @param elsewhere whether a path goes to another handler than the route's: a more specific mapping takes it
         */
        boolean within(String method, String route, java.util.function.Predicate<String> elsewhere) {
            int wildcard = route.indexOf('*');
            if (wildcard < 0) {
                return route.contains("{") && parts.stream().anyMatch(part -> part.syntax() == Syntax.PATH
                        && (part.httpMethod() == null || method.equals("*") || part.httpMethod().equals(method))
                        && !part.matches(method, route, "") && overlaps(route, sample(part.pattern()))
                        && !elsewhere.test(sample(part.pattern())));
            }
            String prefix = route.substring(0, route.lastIndexOf('/', wildcard) + 1);
            return parts.stream().anyMatch(part -> part.syntax() == Syntax.PATH
                    && (part.httpMethod() == null || method.equals("*") || part.httpMethod().equals(method))
                    && literalPrefix(part.pattern()).startsWith(prefix) && !part.matches(method, route, ""));
        }

        /**
         * A path the pattern matches: its wildcards and variables filled in.
         */
        static String sample(String pattern) {
            return pattern.replaceAll("\\{\\*[^}]+}", "x").replaceAll("\\{[^}]+}", "x").replace("**", "x")
                    .replace("*", "x").replace("?", "x");
        }

        /**
         * Whether the route takes the path.
         */
        static boolean overlaps(String route, String sample) {
            try {
                return PathPatternParser.defaultInstance.parse(route).matches(PathContainer.parsePath(sample));
            }
            catch (IllegalArgumentException invalid) {
                return false;
            }
        }

        private static String literalPrefix(String pattern) {
            int end = pattern.length();
            for (char c : new char[] {'*', '{', '?'}) {
                int found = pattern.indexOf(c);
                if (found >= 0) {
                    end = Math.min(end, found);
                }
            }
            return pattern.substring(0, end);
        }

        /**
         * Matches the path, but not once a query string is added: a regex without a trailing {@code .*}.
         */
        boolean missesWithQuery(String method, String path) {
            return matches(method, path) && parts.stream().noneMatch(part -> part.matches(method, path, "?q=1"));
        }

        String describe() {
            if (this.equals(ANY_REQUEST)) {
                return "anyRequest";
            }
            if (this.equals(grpc(List.of("*")))) {
                return "allRequests";
            }
            // Parts with the same method read as one "GET /a,/b".
            StringBuilder text = new StringBuilder();
            String head = null;
            for (Part part : parts) {
                String next = (part.httpMethod() == null ? "" : part.httpMethod() + " ") + switch (part.syntax()) {
                    case REGEX -> "regex ";
                    case DISPATCH -> "dispatcherType ";
                    case TESTS -> "when ";
                    default -> "";
                };
                text.append(next.equals(head) ? part.syntax() == Syntax.TESTS ? " or " : ","
                        : text.isEmpty() ? next : ", " + next).append(part.pattern());
                head = next;
            }
            if (custom != null) {
                text.append(text.isEmpty() ? "" : ", ").append(custom);
            }
            return text.toString();
        }
    }

    /**
     * @param hierarchyAware {@code false} for a {@code WebExpressionAuthorizationManager} built with {@code new}: its
     *        own expression handler has no RoleHierarchy
     * @param customizer the {@code Customizer<HttpSecurity>} bean method that declares the rule, if not the chain
     */
    record Rule(Matcher matcher, Requirement requirement, Integer line, boolean hierarchyAware,
            MethodSignature customizer) {

        Rule(Matcher matcher, Requirement requirement, Integer line) {
            this(matcher, requirement, line, true, null);
        }

        Rule(Matcher matcher, Requirement requirement, Integer line, boolean hierarchyAware) {
            this(matcher, requirement, line, hierarchyAware, null);
        }

        Rule fromCustomizer(MethodSignature beanMethod) {
            return new Rule(matcher, requirement, line, hierarchyAware, beanMethod);
        }
    }

    /**
     * An {@code ignoring().requestMatchers(..)} call in a {@code WebSecurityCustomizer} bean.
     */
    record Ignored(MethodSignature beanMethod, Matcher matcher, Integer line) {
    }

    /**
     * @param securityMatcher the requests this chain handles, {@code null} for all
     * @param errorDispatchUnchecked HTTP-19: its {@code AuthorizationFilter} doesn't check error dispatches
     *        ({@code setFilterErrorDispatch(false)})
     * @param unmatchedAllowed decision 0097: a request no rule matches is let through, as a
     *        {@code FilterSecurityInterceptor} lets a public invocation through, not denied
     * @param condition decision 0111: why the chain's bean may not be made (a profile, a condition AuthTracer
     *        leaves open), {@code null} when it surely is
     */
    record Chain(MethodSignature beanMethod, int order, Matcher securityMatcher, List<Rule> rules,
            boolean authorizes, String mechanism, boolean errorDispatchUnchecked, boolean unmatchedAllowed,
            String condition) {

        Chain(MethodSignature beanMethod, int order, Matcher securityMatcher, List<Rule> rules, boolean authorizes,
                String mechanism) {
            this(beanMethod, order, securityMatcher, rules, authorizes, mechanism, false, false);
        }

        Chain(MethodSignature beanMethod, int order, Matcher securityMatcher, List<Rule> rules, boolean authorizes,
                String mechanism, boolean errorDispatchUnchecked) {
            this(beanMethod, order, securityMatcher, rules, authorizes, mechanism, errorDispatchUnchecked, false);
        }

        Chain(MethodSignature beanMethod, int order, Matcher securityMatcher, List<Rule> rules, boolean authorizes,
                String mechanism, boolean errorDispatchUnchecked, boolean unmatchedAllowed) {
            this(beanMethod, order, securityMatcher, rules, authorizes, mechanism, errorDispatchUnchecked,
                    unmatchedAllowed, null);
        }

        Chain when(String why) {
            return new Chain(beanMethod, order, securityMatcher, rules, authorizes, mechanism, errorDispatchUnchecked,
                    unmatchedAllowed, why);
        }

        /**
         * It surely takes the request: its bean is made, and its {@code securityMatcher}, if any, matches.
         */
        boolean covers(String method, String path) {
            return condition == null && (securityMatcher == null || securityMatcher.matches(method, path));
        }

        /**
         * It may take the request without surely covering it: its {@code securityMatcher} has a part AuthTracer can't
         * evaluate or a lambda's test the caller decides, or (decision 0111) its bean may not be made.
         */
        boolean mayCover(String method, String path) {
            if (condition != null) {
                return securityMatcher == null || securityMatcher.matches(method, path)
                        || securityMatcher.mayMatch(method, path);
            }
            return securityMatcher != null && securityMatcher.mayMatch(method, path);
        }
    }

    private final ScanContext context;
    private final GraphBuilder graph;
    private final List<Chain> chains = new ArrayList<>();
    private final List<Ignored> ignored = new ArrayList<>();
    private final Set<String> withoutHierarchy = new HashSet<>();
    private final List<Rule> customizerRules = new ArrayList<>();
    /**
     * Decision 0111: the customizer beans that may not be made, whose rules may not be there.
     */
    private final Set<MethodSignature> maybeCustomizers = new HashSet<>();
    private final Set<String> reportedMaybe = new HashSet<>();
    /**
     * The paths of the exposed health endpoint Boot's own chain lets everyone reach (its own and its groups' additional
     * ones), once read; empty without one.
     */
    private List<String> healthPaths;
    private boolean customizerAuthorizes;
    private boolean customizerErrorUnchecked;
    /**
     * What customizer beans add besides rules: the login and logout configurers they set, the rules of custom DSLs they
     * apply, and a securityMatcher, which a chain's own replaces.
     */
    private final List<Interpretation> customizerLogins = new ArrayList<>();
    private final List<Rule> customizerDeferred = new ArrayList<>();
    private Matcher customizerSecurityMatcher;
    private final String servletPath;
    private final SecurityDsl dsl;
    private final Interpretation defaultDsls;

    /**
     * RX-01: a WebFlux application's {@code ServerHttpSecurity#authorizeExchange} rules. Same model (ordered, first
     * match wins, no match is denied: 7.1.1 {@code DelegatingReactiveAuthorizationManager}), but its {@code hasRole}
     * is {@code AuthorityReactiveAuthorizationManager.hasRole}: always {@code ROLE_}, never a RoleHierarchy.
     */
    private final boolean reactive;
    private final String mechanism;

    /**
     * @param grpcServices the gRPC services the application serves, for {@code GrpcRequest.toAnyService()}
     */
    HttpSecurityRules(ScanContext context, GraphBuilder graph, SpelRequirements spel, boolean reactive,
            Set<String> grpcServices, SecurityXml.Config xml) {
        this.context = context;
        this.graph = graph;
        this.reactive = reactive;
        this.mechanism = reactive ? "authorizeExchange" : "authorizeHttpRequests";
        this.servletPath = context.properties().get("spring.mvc.servlet.path")
                .map(path -> ("/" + path).replaceAll("/+", "/").replaceAll("/$", "")).orElse("");
        this.dsl = new SecurityDsl(context, reactive ? SecurityDsl.DEFAULT_ROLES : spel, reactive,
                requestMatcherBasePath(), servletPath, grpcServices);
        this.defaultDsls = reactive ? new Interpretation() : dsl.defaultDsls();
        opaque(defaultDsls);
        if (!reactive) {
            managerPostProcessorBean();
        }
        readCustomizers();
        readKotlinDslBeans();
        String chainType = reactive ? WebStack.SECURITY_WEB_FILTER_CHAIN : WebStack.SECURITY_FILTER_CHAIN;
        for (JavaSootMethod method : SpringBeans.beanMethodsOf(context, Set.of(chainType, WEB_SECURITY_CUSTOMIZER))) {
            if (!method.hasBody()) {
                continue;
            }
            if (SpringBeans.assignable(context, (ClassType) method.getReturnType(), Set.of(chainType))) {
                // Decision 0111: a chain whose bean may not be made may take its requests, or leave them to the rest.
                chains.add(chain(method).when(BeanConditions.of(context).maybe(method).orElse(null)));
            } else {
                ignored.addAll(ignoring(method));
            }
        }
        if (!reactive) {
            xmlChains(xml, spel);
        }
        chains.sort(Comparator.comparingInt(Chain::order));
    }

    /**
     * Decision 0036: the XML namespace's {@code <http>} chains, in document order, after any Java ones; a
     * {@code security="none"} one is like {@code ignoring()}. Decision 0097: a {@code request-matcher-ref} bean picks
     * a chain's or a rule's requests; an {@code authorization-manager-ref} bean decides every request of its chain;
     * {@code use-authorization-manager="false"} puts a {@code FilterSecurityInterceptor} there instead.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void xmlChains(SecurityXml.Config xml, SpelRequirements spel) {
        XmlReferences references = new XmlReferences(context, xml);
        for (SecurityXml.Http http : xml.chains()) {
            // Decision 0097: each <http> by its line, so the rules of two chains in one file are told apart.
            MethodSignature source = context.view().getIdentifierFactory().getMethodSignature(
                    context.view().getIdentifierFactory().getClassType(http.file()), "http@" + http.line(), "void",
                    List.of());
            Matcher pattern = http.matcherRef() != null ? references.requestMatcher(http.matcherRef(), servletPath)
                    : http.pattern() == null ? null : http.regex() ? Matcher.regex(null, http.pattern())
                            : Matcher.paths(null, List.of(http.pattern()));
            if (http.none()) {
                if (pattern != null) {
                    ignored.add(new Ignored(source, pattern, http.line()));
                }
                continue;
            }
            if (http.managerRef() != null) {
                // 7.1.1 AuthorizationFilterParser#createAuthorizationManager: the bean is the AuthorizationFilter's
                // manager, and the chain's intercept-urls aren't read.
                String expression = "authorization-manager-ref(" + http.managerRef() + ")";
                Requirement requirement = references.manager(http.managerRef(), expression).orElseGet(() -> {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The <http> at " + http.file() + ":"
                            + http.line() + " hands every request it handles to the AuthorizationManager bean "
                            + http.managerRef() + ", which AuthTracer can't read: they show it as an opaque"
                            + " requirement", MethodNames.codeRef(source).atLine(http.line())));
                    return Requirement.expression(expression);
                });
                chains.add(new Chain(source, Ordered.LOWEST_PRECEDENCE, pattern, List.of(new Rule(
                        Matcher.ANY_REQUEST, requirement, http.line(), false)), true, "authorization-manager-ref"));
                continue;
            }
            List<Rule> rules = http.rules().stream().map(rule -> new Rule(rule.matcherRef() != null
                    ? references.requestMatcher(rule.matcherRef(), servletPath) : rule.regex()
                            ? Matcher.regex(rule.method(), rule.pattern())
                            : Matcher.paths(rule.method(), List.of(rule.pattern())),
                    http.expressions() ? spel.parse(rule.access()) : XmlReferences.attributes(rule.access(), true),
                    rule.line(), http.expressions())).toList();
            // Every <http> gets an AuthorizationFilter, which denies what no intercept-url matches, none at all
            // included (7.1.1 HttpConfigurationBuilder#createFilterSecurity, AuthorizationFilterParser). Decision
            // 0097: a FilterSecurityInterceptor finds no attributes for such a request and, as it doesn't reject
            // public invocations, lets it through (7.2 AbstractSecurityInterceptor).
            chains.add(new Chain(source, Ordered.LOWEST_PRECEDENCE, pattern, rules, true, http.legacy()
                    ? "intercept-url (FilterSecurityInterceptor)" : "intercept-url", false, http.legacy()));
        }
    }

    /**
     * The requests' paths the application's mappings answer, by method: a path a more specific one takes doesn't
     * reach a route with variables that also matches it.
     */
    private final List<Map.Entry<String, String>> handled = new ArrayList<>();

    /**
     * The application's HTTP mappings, as the rules see their paths.
     */
    void handled(List<Ingress> ingresses) {
        ingresses.stream().filter(ingress -> ingress.route() != null && ingress.route().startsWith("/"))
                .forEach(ingress -> handled.add(Map.entry(ingress.httpMethod(),
                        (ownServlet(ingress) ? "" : servletPath) + ingress.route())));
    }

    /**
     * Whether another mapping, more specific than the route (7.0.9 {@code PathPattern.SPECIFICITY_COMPARATOR}),
     * answers the path: Spring MVC picks it, so the route's handler doesn't see that path.
     */
    private boolean elsewhere(String method, String route, String sample) {
        try {
            org.springframework.web.util.pattern.PathPattern own = PathPatternParser.defaultInstance.parse(route);
            PathContainer path = PathContainer.parsePath(sample);
            return handled.stream().filter(entry -> !entry.getValue().equals(route)
                    && (entry.getKey().equals(method) || entry.getKey().equals("*")
                            || method.equals("HEAD") && entry.getKey().equals("GET")))
                    .map(entry -> PathPatternParser.defaultInstance.parse(entry.getValue()))
                    .anyMatch(other -> other.matches(path)
                            && org.springframework.web.util.pattern.PathPattern.SPECIFICITY_COMPARATOR
                                    .compare(other, own) < 0);
        }
        catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    /**
     * Decision 0110: what the question asks, leaving nothing of the asking behind: the nodes, findings and Split parts
     * it adds to the graph, and the rules it notes as reported, are undone.
     */
    <T> T quietly(java.util.function.Supplier<T> question) {
        GraphBuilder.Mark mark = graph.mark();
        Set<String> reported = new HashSet<>(reportedMaybe);
        Set<String> hierarchyless = new HashSet<>(withoutHierarchy);
        try {
            return question.get();
        }
        finally {
            graph.rollback(mark);
            reportedMaybe.retainAll(reported);
            withoutHierarchy.retainAll(hierarchyless);
        }
    }

    /**
     * The request-level check that applies to an Ingress, if any chain covers it.
     */
    Optional<AuthorizationLocation> locationFor(Ingress ingress) {
        String method = ingress.httpMethod();
        // Security matchers see the request path without the context path: the DispatcherServlet's path, then the
        // route. A servlet of its own (a @WebServlet, a registered one, the H2 console) is mapped on the whole path.
        String path = (ownServlet(ingress) ? "" : servletPath) + ingress.route();
        List<AuthorizationLocation> mayIgnore = new ArrayList<>();
        for (Ignored ignore : ignored) {
            if (ignore.matcher().matches(method, path)) {
                return Optional.of(mayIgnoreFirst(mayIgnore, ignoredLocation(ingress, ignore, true)));
            }
            if (ignore.matcher().mayMatch(method, path)) {
                mayIgnore.add(ignoredLocation(ingress, ignore, false));
            }
        }
        Optional<AuthorizationLocation> checked = checkedLocation(ingress, method, path);
        return checked.map(location -> mayIgnoreFirst(mayIgnore, location));
    }

    /**
     * Decision 0051: an {@code ignoring()} matcher that may match the request, without surely matching it, may skip
     * the chains: a Split location of it and the chains' check.
     */
    private AuthorizationLocation mayIgnoreFirst(List<AuthorizationLocation> mayIgnore, AuthorizationLocation then) {
        if (mayIgnore.isEmpty()) {
            return then;
        }
        List<AuthorizationLocation> alternatives = new ArrayList<>(mayIgnore);
        alternatives.add(then);
        return graph.split(new AuthorizationLocation("location:SPLIT:" + then.id() + ":or-ignored:"
                + mayIgnore.stream().map(AuthorizationLocation::id).toList(), "WebSecurityCustomizer ignoring() (may match first and skip the filter chain)",
                Scope.HTTP_REQUEST, Phase.PRE, Requirement.or(alternatives.stream()
                        .map(AuthorizationLocation::requirement).distinct().toList()), then.target(), null,
                String.join(" or ", alternatives.stream().map(AuthorizationLocation::routePattern)
                        .map(pattern -> pattern == null ? "default" : pattern).toList()), Denial.THROW, false),
                GraphBuilder.Split.of(alternatives.stream().map(AuthorizationLocation::id).toList()));
    }

    /**
     * The check of the chain that takes the request, past {@code ignoring()}.
     */
    @Supports({Feature.FINDING_OPAQUE_CONFIG, Feature.FINDING_BYPASSED})
    private Optional<AuthorizationLocation> checkedLocation(Ingress ingress, String method, String path) {
        if (chains.isEmpty()) {
            return withoutChains(ingress, method, path);
        }
        List<AuthorizationLocation> mayCover = new ArrayList<>();
        for (Chain chain : chains) {
            boolean covers = chain.covers(method, path);
            if (!covers && !chain.mayCover(method, path)) {
                continue;
            }
            Optional<AuthorizationLocation> location = chainLocation(ingress, method, path, chain);
            if (covers) {
                // A covering chain that authorizes nothing lets the request through: its own alternative.
                return mayCoverFirst(mayCover, location.isPresent() || mayCover.isEmpty() ? location
                        : Optional.of(unauthorized(chain)));
            }
            mayCover.add(location.orElseGet(() -> unauthorized(chain)));
            Matcher matcher = chain.securityMatcher();
            if (matcher == null) {
                continue;
            }
            if (matcher.mayMatch() && reportedMaybe.add(MethodNames.key(chain.beanMethod()) + ":securityMatcher")) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The SecurityFilterChain "
                        + MethodNames.key(chain.beanMethod()) + " has a securityMatcher AuthTracer can't evaluate ("
                        + describe(matcher) + "): the requests it matches get its rules instead of the chains after"
                        + " it", MethodNames.codeRef(chain.beanMethod())));
            }
            else if (matcher.callerDecides()
                    && reportedMaybe.add(MethodNames.key(chain.beanMethod()) + ":securityMatcher")) {
                graph.finding(new Finding(Finding.Kind.BYPASSED, "The SecurityFilterChain "
                        + MethodNames.key(chain.beanMethod()) + " has a securityMatcher (" + describe(matcher)
                        + ") that depends on what the caller sends (" + String.join("; ", matcher.callerChoices())
                        + "): a caller picks whether its request gets the chain's rules or the chains after it",
                        MethodNames.codeRef(chain.beanMethod())));
            }
        }
        // Decision 0111: when every chain's bean may not be made, none may be, and the default chain takes the request.
        return mayCoverFirst(mayCover, chains.stream().allMatch(chain -> chain.condition() != null)
                ? withoutChains(ingress, method, path) : Optional.empty());
    }

    /**
     * The check when the application makes no chain: Boot's or Spring Security's default chain, with the rules of
     * {@code Customizer<HttpSecurity>} beans; none without either.
     */
    private Optional<AuthorizationLocation> withoutChains(Ingress ingress, String method, String path) {
        Optional<AuthorizationLocation> boot = bootDefault();
        List<Integer> maybe = new ArrayList<>();
        for (int i = 0; boot.isPresent() && i < customizerRules.size(); i++) {
            Rule rule = customizerRules.get(i);
            if (rule.matcher().matches(method, path) && sure(rule)) {
                queryBypass(ingress, path, null, customizerRules, i, boot.get().requirement());
                return Optional.of(maybeFirst(null, customizerRules, maybe, mechanism, location(null, i, rule)));
            }
            if (rule.matcher().mayMatch(method, path) || rule.matcher().matches(method, path)) {
                maybe.add(i);
            }
        }
        return boot.isPresent() ? Optional.of(maybeFirst(null, customizerRules, maybe, mechanism,
                bootHealth(method, path).orElse(boot.get()))) : boot;
    }

    /**
     * HTTP-17 (decision 0070): the chains whose own filters a request may pass, in order: those whose
     * {@code securityMatcher} may take it first, then the one that covers it; none when {@code ignoring()} takes it.
     *
     * @param surely the request passes them: one chain covers it, and no {@code ignoring()} or
     *        {@code securityMatcher} AuthTracer can't evaluate may take it elsewhere
     */
    record Passes(List<MethodSignature> chains, boolean surely) {
    }

    @Supports(Feature.CALL_PATHS)
    Passes chainsFor(Ingress ingress) {
        String method = ingress.httpMethod();
        String path = (ownServlet(ingress) ? "" : servletPath) + ingress.route();
        if (ignored.stream().anyMatch(ignore -> ignore.matcher().matches(method, path))) {
            return new Passes(List.of(), true);
        }
        boolean surely = ignored.stream().noneMatch(ignore -> ignore.matcher().mayMatch(method, path));
        List<MethodSignature> passed = new ArrayList<>();
        for (Chain chain : chains) {
            if (chain.covers(method, path)) {
                passed.add(chain.beanMethod());
                return new Passes(passed, surely && passed.size() == 1);
            }
            if (chain.mayCover(method, path)) {
                passed.add(chain.beanMethod());
            }
        }
        return new Passes(passed, false);
    }

    private boolean ownServlet(Ingress ingress) {
        return !servletPath.isEmpty() && ingress.handler() != null && SpringBeans.assignable(context,
                context.type(ingress.handler().className()), Set.of(HTTP_SERVLET));
    }

    /**
     * The chain's rule for the request: the first that matches, else its default denial; empty when the chain
     * doesn't authorize requests.
     */
    private Optional<AuthorizationLocation> chainLocation(Ingress ingress, String method, String path, Chain chain) {
        if (!chain.authorizes()) {
            return Optional.empty();
        }
        AuthorizationLocation request = dispatchLocation(ingress, method, path, chain, REQUEST);
        if (!errorPage(ingress)) {
            return Optional.of(request);
        }
        AuthorizationLocation error = chain.errorDispatchUnchecked() ? graph.node(new AuthorizationLocation(
                "location:HTTP_REQUEST:" + MethodNames.key(chain.beanMethod()) + ":error-dispatch",
                chain.mechanism() + " (error dispatches are not checked: setFilterErrorDispatch(false))",
                Scope.HTTP_REQUEST, Phase.PRE, Requirement.permitAll(), MethodNames.codeRef(chain.beanMethod()), null,
                "error dispatch", Denial.THROW, false))
                : dispatchLocation(ingress, method, path, chain, ERROR);
        if (error.requirement().equals(request.requirement())) {
            return Optional.of(request);
        }
        return Optional.of(graph.split(new AuthorizationLocation("location:SPLIT:" + request.id() + ":or-error:"
                + error.id(), chain.mechanism() + " (an error dispatch also reaches the error page)",
                Scope.HTTP_REQUEST, Phase.PRE, Requirement.or(List.of(request.requirement(), error.requirement())),
                request.target(), null, request.routePattern() + " or, on an error, " + error.routePattern(),
                Denial.THROW, false), GraphBuilder.Split.of(List.of(request.id(), error.id()))));
    }

    /**
     * HTTP-05: Boot's error page (an application controller on {@code spring.web.error.path}, 4.1.1
     * {@code ErrorMvcAutoConfiguration$ErrorPageCustomizer}) is also reached by the {@code ERROR} dispatch of any
     * request that fails, one Spring Security denies included, with that request's method. Boot registers the filter
     * chain for every dispatcher type (4.1.1 {@code SecurityFilterProperties}), so the rules see that dispatch too.
     */
    @Might("Follow forwards: a forward: view or RequestDispatcher#forward reaches its target under the FORWARD"
            + " dispatch's rule, which dispatcherTypeMatchers(FORWARD).permitAll() opens")
    private boolean errorPage(Ingress ingress) {
        if (reactive || !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)) {
            return false;
        }
        String errorPath = context.properties().get("spring.web.error.path").orElse("/error");
        return ingress.route().equals(errorPath);
    }

    /**
     * The chain's rule for one dispatch of the request.
     */
    private AuthorizationLocation dispatchLocation(Ingress ingress, String method, String path, Chain chain,
            String dispatch) {
        List<Integer> maybe = new ArrayList<>();
        // A route that is a pattern: narrower rules before the one it matches take part of its requests.
        List<Integer> within = new ArrayList<>();
        for (int i = 0; i < chain.rules().size(); i++) {
            Rule rule = chain.rules().get(i);
            if (rule.matcher().matches(method, path, dispatch) && sure(rule)) {
                if (dispatch.equals(REQUEST)) {
                    queryBypass(ingress, path, chain.beanMethod(), chain.rules(), i, chain.unmatchedAllowed()
                            ? Requirement.permitAll() : Requirement.denyAll());
                }
                return maybeFirst(chain.beanMethod(), chain.rules(), maybe, within, chain.mechanism(),
                        location(chain.beanMethod(), i, rule, chain.mechanism()));
            }
            if (rule.matcher().mayMatch(method, path) || rule.matcher().matches(method, path, dispatch)) {
                maybe.add(i);
            }
            else if (rule.matcher().within(method, path, sample -> elsewhere(method, path, sample))) {
                within.add(i);
            }
        }
        return maybeFirst(chain.beanMethod(), chain.rules(), maybe, within, chain.mechanism(),
                graph.node(new AuthorizationLocation(
                        "location:HTTP_REQUEST:" + MethodNames.key(chain.beanMethod()) + ":unmatched",
                        chain.mechanism() + (chain.unmatchedAllowed() ? " (no rule matched: let through)"
                                : " (no rule matched: denied by default)"), Scope.HTTP_REQUEST,
                        Phase.PRE, chain.unmatchedAllowed() ? Requirement.permitAll() : Requirement.denyAll(),
                        MethodNames.codeRef(chain.beanMethod()), null, "unmatched", Denial.THROW, false)));
    }

    /**
     * A chain that checks no rule lets any caller through.
     */
    private AuthorizationLocation unauthorized(Chain chain) {
        return graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + MethodNames.key(chain.beanMethod())
                + ":no-rules", chain.mechanism() + " (the chain authorizes no request)", Scope.HTTP_REQUEST,
                Phase.PRE, Requirement.permitAll(), MethodNames.codeRef(chain.beanMethod()), null, "no rules",
                Denial.THROW, false));
    }

    /**
     * Decision 0027: chains before the one that covers the request whose {@code securityMatcher} AuthTracer can't
     * evaluate may take the request first, so it needs one of their checks or the covering chain's (none when no
     * chain covers it): a Split location asking for the weakest.
     */
    private Optional<AuthorizationLocation> mayCoverFirst(List<AuthorizationLocation> mayCover,
            Optional<AuthorizationLocation> covering) {
        if (mayCover.isEmpty()) {
            return covering;
        }
        List<AuthorizationLocation> alternatives = new ArrayList<>(mayCover);
        alternatives.add(covering.orElseGet(() -> graph.node(new AuthorizationLocation(
                "location:HTTP_REQUEST:no-chain", mechanism + " (no SecurityFilterChain covers the request)",
                Scope.HTTP_REQUEST, Phase.PRE, Requirement.permitAll(), mayCover.getFirst().target(), null,
                "no chain", Denial.THROW, false))));
        List<Requirement> requirements = alternatives.stream().map(AuthorizationLocation::requirement).distinct()
                .toList();
        AuthorizationLocation last = alternatives.getLast();
        return Optional.of(graph.split(new AuthorizationLocation("location:SPLIT:" + last.id() + ":or-chains:"
                + mayCover.stream().map(AuthorizationLocation::id).toList(), mechanism
                + " (a securityMatcher may match first)", Scope.HTTP_REQUEST, Phase.PRE, requirements.size() == 1
                        ? requirements.getFirst() : Requirement.or(requirements), last.target(), null,
                String.join(" or ", alternatives.stream().map(AuthorizationLocation::routePattern)
                        .map(pattern -> pattern == null ? "default" : pattern).toList()), Denial.THROW, false),
                GraphBuilder.Split.of(alternatives.stream().map(AuthorizationLocation::id).toList())));
    }

    /**
     * Whether the rule is surely there: not one of a customizer bean that may not be made (decision 0111), which may
     * take the requests it matches or leave them to the rules after it.
     */
    private boolean sure(Rule rule) {
        return rule.customizer() == null || !maybeCustomizers.contains(rule.customizer());
    }

    /**
     * HTTP-06: rules before the one that matches whose {@code RequestMatcher} AuthTracer can't evaluate may match the
     * request first, so it needs one of their requirements or the matching rule's: a Split location (decision 0027)
     * asking for the weakest, and an OPAQUE_CONFIG finding per such rule.
     */
    private AuthorizationLocation maybeFirst(MethodSignature chainMethod, List<Rule> rules, List<Integer> maybe,
            String chainMechanism, AuthorizationLocation matched) {
        return maybeFirst(chainMethod, rules, maybe, List.of(), chainMechanism, matched);
    }

    /**
     * @param within rules narrower than a route that is a pattern, which match part of its requests: alternatives
     *        too, but known ones, so no finding
     */
    @Supports({Feature.FINDING_OPAQUE_CONFIG, Feature.FINDING_BYPASSED})
    private AuthorizationLocation maybeFirst(MethodSignature chainMethod, List<Rule> rules, List<Integer> maybe,
            List<Integer> within, String chainMechanism, AuthorizationLocation matched) {
        if (maybe.isEmpty() && within.isEmpty()) {
            return matched;
        }
        List<AuthorizationLocation> alternatives = new ArrayList<>();
        for (int index : new java.util.TreeSet<>(java.util.stream.Stream.concat(maybe.stream(), within.stream())
                .toList())) {
            Rule rule = rules.get(index);
            AuthorizationLocation location = location(chainMethod, index, rule, chainMechanism);
            alternatives.add(location);
            if (maybe.contains(index) && rule.matcher().mayMatch() && reportedMaybe.add(location.id())) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The rule " + describe(rule.matcher())
                        + " (requires " + describe(rule.requirement()) + ") uses a RequestMatcher AuthTracer can't"
                        + " evaluate: the requests it matches get it instead of the rules after it",
                        location.target()));
            }
            else if (maybe.contains(index) && rule.matcher().callerDecides() && reportedMaybe.add(location.id())) {
                graph.finding(new Finding(Finding.Kind.BYPASSED, "The rule " + describe(rule.matcher())
                        + " (requires " + describe(rule.requirement()) + ") depends on what the caller sends ("
                        + String.join("; ", rule.matcher().callerChoices()) + "): a caller picks whether its request"
                        + " gets it or the rules after it", location.target()));
            }
        }
        alternatives.add(matched);
        List<Requirement> requirements = alternatives.stream().map(AuthorizationLocation::requirement).distinct()
                .toList();
        String id = "location:SPLIT:" + matched.id() + (maybe.isEmpty() ? "" : ":or:" + maybe)
                + (within.isEmpty() ? "" : ":within:" + within);
        String why = maybe.isEmpty() ? " (narrower rules match part of the route)"
                : maybe.stream().allMatch(index -> !sure(rules.get(index)))
                        ? " (a customizer bean that may not be made may match first)"
                        : " (a RequestMatcher may match first)";
        return graph.split(new AuthorizationLocation(id, chainMechanism + why,
                Scope.HTTP_REQUEST, Phase.PRE,
                requirements.size() == 1 ? requirements.getFirst() : Requirement.or(requirements), matched.target(),
                null, String.join(" or ", alternatives.stream().map(AuthorizationLocation::routePattern)
                        .map(pattern -> pattern == null ? "default" : pattern).toList()), Denial.THROW, false),
                GraphBuilder.Split.of(alternatives.stream().map(AuthorizationLocation::id).toList()));
    }

    /**
     * HTTP-03: {@code RegexRequestMatcher} matches the query string too, so a regex without a trailing {@code .*}
     * stops matching once a request adds {@code ?anything}, and the request falls through to the next rule.
     *
     * @param fallback what a request that matches no later rule gets
     */
    @Supports(Feature.FINDING_BYPASSED)
    private void queryBypass(Ingress ingress, String path, MethodSignature chainMethod, List<Rule> rules, int index,
            Requirement fallback) {
        Rule rule = rules.get(index);
        // Decision 0093: an exact URL only lets everyone in; a query string takes the request to a later rule, which
        // asks for no less.
        if (!rule.matcher().missesWithQuery(ingress.httpMethod(), path)
                || rule.matcher().parts().stream().anyMatch(part -> part.syntax() == Matcher.Syntax.EXACT)) {
            return;
        }
        Rule next = rules.subList(index + 1, rules.size()).stream()
                .filter(later -> later.matcher().parts().stream()
                        .anyMatch(part -> part.matches(ingress.httpMethod(), path, "?q=1")))
                .findFirst().orElse(null);
        Requirement instead = next == null ? fallback : next.requirement();
        if (instead.equals(rule.requirement())) {
            return;
        }
        graph.finding(new Finding(Finding.Kind.BYPASSED, "On " + ingress.endpoint()
                + ": the regex rule " + rule.matcher().describe() + " (requires " + describe(rule.requirement())
                + ") does not match once the request has a query string (RegexRequestMatcher matches it too), so "
                + ingress.route() + "?any=1 gets " + (next == null ? "the default" : "rule " + next.matcher()
                        .describe()) + " instead (" + describe(instead) + ")",
                MethodNames.codeRef(rule.customizer() != null ? rule.customizer() : chainMethod).atLine(rule.line())));
    }

    /**
     * Whether a RoleHierarchy bean widens this rule's role checks.
     */
    @Supports(Feature.REQUIREMENTS)
    boolean hierarchyAware(AuthorizationLocation location) {
        return !withoutHierarchy.contains(location.id());
    }

    /**
     * A rule from a {@code Customizer<HttpSecurity>} bean is one Location shared by every chain it applies to.
     */
    private AuthorizationLocation location(MethodSignature chainMethod, int index, Rule rule) {
        return location(chainMethod, index, rule, mechanism);
    }

    private AuthorizationLocation location(MethodSignature chainMethod, int index, Rule rule, String mechanism) {
        MethodSignature declaredIn = rule.customizer() != null ? rule.customizer() : chainMethod;
        String pattern = describe(rule.matcher());
        String id = "location:HTTP_REQUEST:" + MethodNames.key(declaredIn) + ":" + index + ":" + pattern;
        if (!rule.hierarchyAware()) {
            withoutHierarchy.add(id);
        }
        CodeRef target = MethodNames.codeRef(declaredIn).atLine(rule.line());
        return graph.node(new AuthorizationLocation(id, mechanism, Scope.HTTP_REQUEST, Phase.PRE, rule.requirement(),
                target, null, pattern, Denial.THROW, false));
    }

    /**
     * The matcher as the DSL names it: {@code anyExchange} on WebFlux.
     */
    private String describe(Matcher matcher) {
        return reactive && matcher.equals(Matcher.ANY_REQUEST) ? "anyExchange" : matcher.describe();
    }

    /**
     * No filter runs, so nothing authenticates the caller or checks a rule: recorded as {@code permitAll}, with a
     * BYPASSED finding because it is weaker still (no CSRF protection, no security headers, no SecurityContext).
     *
     * @param matched whether the matcher surely matches; one that may is reported once, on the bean
     */
    @Supports(Feature.FINDING_BYPASSED)
    private AuthorizationLocation ignoredLocation(Ingress ingress, Ignored ignore, boolean matched) {
        CodeRef target = MethodNames.codeRef(ignore.beanMethod()).atLine(ignore.line());
        if (matched) {
            graph.finding(new Finding(Finding.Kind.BYPASSED, "On " + ingress.endpoint()
                    + ": ignoring() in " + MethodNames.key(ignore.beanMethod()) + " matches "
                    + ignore.matcher().describe() + ", so the request skips every SecurityFilterChain (no"
                    + " authentication, no authorizeHttpRequests rule); permitAll() keeps the filter chain", target));
        }
        return graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + MethodNames.key(ignore.beanMethod())
                + ":ignoring:" + ignore.matcher().describe(), IGNORING, Scope.HTTP_REQUEST, Phase.PRE,
                Requirement.permitAll(), target, null, ignore.matcher().describe(), Denial.THROW, false));
    }

    /**
     * HTTP-20: the Kotlin DSL's own beans, {@code HttpSecurityDsl.() -> Unit} and then
     * {@code AuthorizeHttpRequestsDsl.() -> Unit} (reactive: {@code ServerHttpSecurityDsl}, {@code AuthorizeExchangeDsl}),
     * each in {@code @Order}. 7.1.1's {@code HttpSecurityDsl} applies them when it is created, so they apply to every
     * chain configured with {@code http { }}, ahead of its own rules.
     */
    private void readKotlinDslBeans() {
        String kotlin = reactive ? "org.springframework.security.config.web.server."
                : "org.springframework.security.config.annotation.web.";
        for (String type : reactive ? List.of(kotlin + "ServerHttpSecurityDsl", kotlin + "AuthorizeExchangeDsl")
                : List.of(kotlin + "HttpSecurityDsl", kotlin + "AuthorizeHttpRequestsDsl")) {
            boolean rules = type.endsWith("AuthorizeHttpRequestsDsl") || type.endsWith("AuthorizeExchangeDsl");
            for (Interpretation bean : lambdaBeans(Set.of(KOTLIN_FUNCTION_1), type,
                    rules ? Receiver.KOTLIN_RULES : Receiver.HTTP, rules)) {
                dsl.startKotlinChainsWith(bean.rules, bean.authorizes);
            }
        }
    }

    /**
     * HTTP-15: {@code Customizer<HttpSecurity>} (and {@code ThrowingCustomizer}) beans, then top-level customizer
     * beans for {@code authorizeHttpRequests} ({@code Customizer<AuthorizationManagerRequestMatcherRegistry>}).
     * Spring Security 7.1.1's {@code HttpSecurityConfiguration#httpSecurity} applies both kinds, each in
     * {@code @Order}, to the prototype {@code HttpSecurity} before a chain method (or Boot's default chain) gets it,
     * so their rules come first.
     */
    private void readCustomizers() {
        // RX-04: the same two kinds for ServerHttpSecurity (7.1.1 ServerHttpSecurityConfiguration#httpSecurity).
        for (String type : reactive ? List.of(SERVER_HTTP_SECURITY, AUTHORIZE_EXCHANGE_SPEC)
                : List.of(SpringNames.HTTP_SECURITY, REGISTRY)) {
            boolean registry = type.equals(REGISTRY) || type.equals(AUTHORIZE_EXCHANGE_SPEC);
            for (Interpretation customizer : lambdaBeans(CUSTOMIZERS, type,
                    registry ? Receiver.REGISTRY : Receiver.HTTP, registry)) {
                customizerRules.addAll(customizer.rules);
                customizerAuthorizes |= customizer.authorizes;
                customizerErrorUnchecked |= customizer.errorDispatchUnchecked;
                opaque(customizer);
                customizerLogins.add(customizer);
                customizerDeferred.addAll(customizer.deferred);
                if (customizer.securityMatcher != null) {
                    customizerSecurityMatcher = customizer.securityMatcher;
                }
            }
        }
    }

    /**
     * The {@code @Bean} lambdas declared as one of the types over {@code receiver} (their first type argument), each
     * read as {@code as}, in {@code @Order}. With {@code authorizes}, each one decides requests even without rules.
     */
    private List<Interpretation> lambdaBeans(Set<String> types, String receiver, Receiver as, boolean authorizes) {
        List<Map.Entry<Integer, Interpretation>> beans = new ArrayList<>();
        for (JavaSootMethod method : SpringBeans.beanMethods(context, types)) {
            boolean typed = method.hasBody() && context.classFiles().genericReturnType(method.getSignature())
                    .filter(generic -> !generic.arguments().isEmpty()
                            && generic.arguments().getFirst().name().equals(receiver)).isPresent();
            if (typed) {
                Interpretation result = dsl.lambdas(method, receiver, as);
                result.authorizes |= authorizes;
                result.rules.replaceAll(rule -> rule.fromCustomizer(method.getSignature()));
                if (BeanConditions.of(context).maybe(method).isPresent()) {
                    maybeCustomizers.add(method.getSignature());
                }
                beans.add(Map.entry(order(context, method), result));
            }
        }
        beans.sort(Map.Entry.comparingByKey());
        return beans.stream().map(Map.Entry::getValue).toList();
    }

    /**
     * HTTP-04: a single {@code PathPatternRequestMatcher.Builder} bean builds every {@code requestMatchers(String)},
     * {@code securityMatcher(String)} and {@code ignoring()} pattern, so its {@code basePath} prefixes them all
     * ({@code AbstractRequestMatcherRegistry#getRequestMatcherBuilder} takes it {@code getIfUnique}). Published as
     * the builder itself or as a {@code PathPatternRequestMatcherBuilderFactoryBean}.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private String requestMatcherBasePath() {
        List<JavaSootMethod> beans = SpringBeans.beanMethods(context, SecurityDsl.MATCHER_BUILDER,
                MATCHER_BUILDER_FACTORY).stream().filter(JavaSootMethod::hasBody).toList();
        if (beans.isEmpty() && !reactive && !servletPath.isEmpty()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)
                && context.findClass(BOOT_DEFAULT_CHAIN).isPresent()) {
            // Boot 4.1.1's own Builder bean (PathPatternRequestMatcherBuilderConfiguration, when the application
            // declares none): PathPatternRequestMatcher.withDefaults().basePath(the DispatcherServlet's path).
            return servletPath;
        }
        if (beans.size() != 1) {
            return null;
        }
        for (Stmt stmt : beans.getFirst().getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && Set.of("basePath", "setBasePath").contains(invoke.get().getMethodSignature()
                    .getName()) && invoke.get().getArgCount() == 1) {
                // A constant, or the configuration's value (@Value("${spring.mvc.servlet.path}"), say).
                String base = new ConfiguredValues(context).of(beans.getFirst(), invoke.get().getArg(0)).value();
                if (base != null) {
                    return base;
                }
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The PathPatternRequestMatcher.Builder bean "
                        + MethodNames.key(beans.getFirst().getSignature()) + " sets a basePath that is neither a"
                        + " constant nor a property AuthTracer can read; request rules are matched without it",
                        MethodNames.codeRef(beans.getFirst().getSignature())));
            }
        }
        return null;
    }

    /**
     * The {@code WebSecurity} lambdas a {@code WebSecurityCustomizer} bean method returns.
     */
    @Supports(Feature.FINDING_BYPASSED)
    private List<Ignored> ignoring(JavaSootMethod beanMethod) {
        Interpretation result = dsl.lambdas(beanMethod, WEB_SECURITY, Receiver.WEB);
        List<Ignored> found = new ArrayList<>();
        for (Rule rule : result.ignored) {
            Ignored ignore = new Ignored(beanMethod.getSignature(), rule.matcher(), rule.line());
            if (rule.matcher().custom() != null) {
                graph.finding(new Finding(Finding.Kind.BYPASSED, "ignoring() in " + MethodNames.key(beanMethod
                        .getSignature()) + " uses a RequestMatcher AuthTracer can't evaluate; the requests it"
                        + " matches skip every SecurityFilterChain", MethodNames.codeRef(beanMethod.getSignature())
                        .atLine(rule.line())));
            }
            else if (rule.matcher().callerDecides()) {
                graph.finding(new Finding(Finding.Kind.BYPASSED, "ignoring() in " + MethodNames.key(beanMethod
                        .getSignature()) + " matches " + rule.matcher().describe() + ", which depends on what the"
                        + " caller sends (" + String.join("; ", rule.matcher().callerChoices()) + "): a caller who"
                        + " sends it skips every SecurityFilterChain", MethodNames.codeRef(beanMethod.getSignature())
                        .atLine(rule.line())));
            }
            found.add(ignore);
        }
        return found;
    }

    /**
     * Decision 0041: with Actuator, Spring Boot's own chain (7.1.1 {@code ManagementWebSecurityAutoConfiguration}, or
     * its reactive twin) lets everyone reach the health endpoint, when it is exposed, before authenticating the rest.
     * Not when one of Boot's OAuth2 chains takes the default chain's place: Boot makes those first, and then no
     * Actuator chain.
     */
    private Optional<AuthorizationLocation> bootHealth(String method, String path) {
        String management = reactive ? REACTIVE_MANAGEMENT_SECURITY : MANAGEMENT_SECURITY;
        if (healthPaths == null) {
            ActuatorEndpoints actuator = new ActuatorEndpoints(context);
            healthPaths = new ArrayList<>();
            if (context.findClass(management).isPresent() && actuator.active()
                    && actuator.exposed().containsKey("health")
                    && !AuthenticationMechanisms.bootOAuth2DefaultChain(context)) {
                String health = servletPath + actuator.path("health");
                healthPaths.addAll(List.of(health, health + "/**"));
                // EndpointRequest.toAdditionalPaths(WebServerNamespace.SERVER, HealthEndpoint.class)
                actuator.additionalHealthPaths("server").forEach(extra -> healthPaths.add(servletPath + extra));
            }
        }
        if (healthPaths.isEmpty() || !Matcher.paths(null, healthPaths).matches(method, path)) {
            return Optional.empty();
        }
        return Optional.of(graph.node(new AuthorizationLocation("location:HTTP_REQUEST:spring-boot-default:health",
                reactive ? "Spring Security default SecurityWebFilterChain" : "Spring Boot default SecurityFilterChain",
                Scope.HTTP_REQUEST, Phase.PRE, Requirement.permitAll(), CodeRef.ofClass(management), null,
                "EndpointRequest.to(HealthEndpoint)", Denial.THROW, false)));
    }

    /**
     * Spring Boot's own chain when the application defines none: every request must be authenticated.
     * Only applies when the application uses auto-configuration and Boot's security module is on the classpath.
     */
    private Optional<AuthorizationLocation> bootDefault() {
        boolean autoConfigured = context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION);
        if (reactive) {
            // @EnableWebFluxSecurity (yours, or Boot's when it auto-configures) builds anyExchange().authenticated().
            boolean enabled = context.anyClassAnnotated(WebStack.ENABLE_WEBFLUX_SECURITY)
                    || autoConfigured && context.findClass(BOOT_REACTIVE_SECURITY).isPresent();
            return !enabled ? Optional.empty() : Optional.of(graph.node(new AuthorizationLocation(
                    "location:HTTP_REQUEST:webflux-default:anyExchange", "Spring Security default SecurityWebFilterChain",
                    Scope.HTTP_REQUEST, Phase.PRE, Requirement.authenticated(), CodeRef.ofClass(WEBFLUX_DEFAULT_CHAIN),
                    null, "anyExchange", Denial.THROW, false)));
        }
        if (autoConfigured && context.findClass(BOOT_DEFAULT_CHAIN).isPresent()) {
            return Optional.of(graph.node(new AuthorizationLocation(
                    "location:HTTP_REQUEST:spring-boot-default:anyRequest", "Spring Boot default SecurityFilterChain",
                    Scope.HTTP_REQUEST, Phase.PRE, Requirement.authenticated(), CodeRef.ofClass(BOOT_DEFAULT_CHAIN),
                    null, "anyRequest", Denial.THROW, false)));
        }
        // Without Boot, @EnableWebSecurity with no chain bean gets Spring Security's own: anyRequest().authenticated()
        // with form login and HTTP Basic (7.1.1 WebSecurityConfiguration#springSecurityFilterChain).
        boolean enabled = context.anyClassAnnotated(WebStack.ENABLE_WEB_SECURITY);
        return !enabled ? Optional.empty() : Optional.of(graph.node(new AuthorizationLocation(
                "location:HTTP_REQUEST:spring-security-default:anyRequest", "Spring Security default SecurityFilterChain",
                Scope.HTTP_REQUEST, Phase.PRE, Requirement.authenticated(), CodeRef.ofClass(SERVLET_DEFAULT_CHAIN), null,
                "anyRequest", Denial.THROW, false)));
    }

    /**
     * A bean method's {@code @Order}, lowest precedence without one.
     */
    static int order(ScanContext context, JavaSootMethod beanMethod) {
        return context.findAnnotation(beanMethod, ORDER).flatMap(order -> Annotations.integer(order, "value"))
                .orElse(Ordered.LOWEST_PRECEDENCE);
    }

    /**
     * The configuration the DSL couldn't read, as OPAQUE_CONFIG findings.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void opaque(Interpretation interpretation) {
        for (SecurityDsl.Note note : interpretation.opaque) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, note.message(), note.where()));
        }
    }

    /**
     * HTTP-19: a unique {@code ObjectPostProcessor<AuthorizationManager<HttpServletRequest>>} bean post-processes the
     * manager of every chain's {@code authorizeHttpRequests} (7.1.1 {@code AuthorizeHttpRequestsConfigurer} takes it
     * {@code ifUnique}).
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void managerPostProcessorBean() {
        List<JavaSootMethod> beans = SpringBeans.beanMethods(context, SecurityDsl.OBJECT_POST_PROCESSOR).stream()
                .filter(method -> context.classFiles().genericReturnType(method.getSignature())
                        .equals(Optional.of(REQUEST_MANAGER_POST_PROCESSOR)))
                .toList();
        if (beans.size() == 1) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The ObjectPostProcessor bean "
                    + MethodNames.key(beans.getFirst().getSignature()) + " post-processes every authorizeHttpRequests"
                    + " AuthorizationManager, which it may replace or wrap: requests may not be decided by the rules"
                    + " shown", MethodNames.codeRef(beans.getFirst().getSignature())));
        }
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private Chain chain(JavaSootMethod beanMethod) {
        Interpretation result = dsl.chain(beanMethod);
        opaque(result);
        for (SecurityDsl.Unread unread : result.unread) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The rule " + describe(unread.matcher()) + " in "
                    + MethodNames.key(beanMethod.getSignature()) + " asks for " + unread.requirement()
                    + ", which AuthTracer can't read: the requests it matches get it as an opaque requirement",
                    MethodNames.codeRef(beanMethod.getSignature())));
        }
        // PermitAllSupport adds the login and logout URLs first, when the chain is built; custom DSLs' rules come
        // after the chain's own, spring.factories ones first (they were applied first).
        List<Interpretation> configurers = new ArrayList<>(List.of(defaultDsls));
        configurers.addAll(customizerLogins);
        configurers.add(result);
        List<Rule> rules = new ArrayList<>(SecurityDsl.permitted(configurers));
        rules.addAll(customizerRules);
        rules.addAll(result.rules);
        rules.addAll(defaultDsls.deferred);
        rules.addAll(customizerDeferred);
        rules.addAll(result.deferred);
        return new Chain(beanMethod.getSignature(), order(context, beanMethod), result.securityMatcher != null
                ? result.securityMatcher : customizerSecurityMatcher, rules,
                result.authorizes || customizerAuthorizes || defaultDsls.authorizes, mechanism,
                result.errorDispatchUnchecked || customizerErrorUnchecked || defaultDsls.errorDispatchUnchecked);
    }

    /**
     * A requirement as findings name it: {@code permitAll}, {@code ROLE_ADMIN}, its expression.
     */
    static String describe(Requirement requirement) {
        if (requirement.expression() != null) {
            return requirement.expression();
        }
        return switch (requirement.kind()) {
            case PERMIT_ALL -> "permitAll";
            case DENY_ALL -> "denyAll";
            case AUTHENTICATED -> "authenticated";
            case FULLY_AUTHENTICATED -> "fullyAuthenticated";
            case REMEMBER_ME -> "rememberMe";
            default -> requirement.authorities().isEmpty() ? requirement.kind().name().toLowerCase()
                    : String.join(",", requirement.authorities());
        };
    }
}
