package dev.crain.authtracer.link;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Issuer;
import dev.crain.authtracer.graph.Observation;
import dev.crain.authtracer.graph.Registration;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Links application graphs into a system graph: statically (egress URL templates against other services' routes)
 * and from traces (client spans and the server spans they call, producer spans and the consumer spans that received
 * the message), then connects the fields that travel over each link by their JSON names. Spring Security's
 * authorization spans are matched back to the static Locations.
 */
@Supports(Feature.SYSTEM_GRAPH)
public final class Linker {

    private static final int DEFAULT_PORT = 8080;

    /**
     * Message brokers' kinds: Kafka topics, Rabbit queues, JMS destinations (decision 0044).
     */
    private static final Set<String> MESSAGING = Set.of("KAFKA", "RABBIT", "JMS");
    private static final Set<String> SCOPE_CLAIMS = Set.of("scope", "scp");

    private static final Logger log = LoggerFactory.getLogger(Linker.class);

    /**
     * Request-level decisions: a Servlet request, or a WebFlux exchange (7.1.1
     * {@code AuthorizationObservationConvention} names them by the object authorized).
     */
    private static final Set<String> AUTHORIZE_REQUEST = Set.of("authorize request", "authorize exchange");
    private static final String AUTHORIZE_METHOD = "authorize method";
    private static final String DECISION = "spring.security.authorization.decision";
    private static final String DECISION_DETAILS = "spring.security.authorization.decision.details";
    private static final Pattern EXPRESSION = Pattern.compile("expressionAttribute=(.*)]\\s*$");
    private static final Pattern AUTHORITIES = Pattern.compile("authorities=\\[([^\\]]*)]");
    private static final int MAX_FIELD_DEPTH = 5;
    /**
     * Micrometer's JMS tags (1.17.1, {@code JmsObservationDocumentation}): whether the destination is temporary, on
     * every JMS span; and the destination name it gives when the message names none it can read.
     */
    private static final String JMS_TEMPORARY = "messaging.destination.temporary";
    private static final String JMS_UNKNOWN = "unknown";
    /**
     * A span's HTTP method: Micrometer's tag, then OpenTelemetry's current and older ones.
     */
    private static final String[] METHOD_TAGS = { "method", "http.request.method", "http.method" };
    /**
     * A client span's full URL, in OpenTelemetry's older and current tags; Micrometer's {@code uri} is a template.
     */
    private static final String[] CLIENT_URL_TAGS = { "http.url", "url.full" };

    /**
     * The authorities a decision says its check asked for, e.g. {@code authorities=[ROLE_ADMIN]}; empty when it names
     * none (an expression, {@code authenticated}).
     */
    @Supports(Feature.IDENTITIES)
    static Set<String> askedAuthorities(String details) {
        Matcher authorities = AUTHORITIES.matcher(details);
        Set<String> asked = new TreeSet<>();
        if (authorities.find()) {
            for (String authority : authorities.group(1).split(",")) {
                if (!authority.isBlank()) {
                    asked.add(authority.trim());
                }
            }
        }
        return asked;
    }

    @Supports(Feature.IDENTITIES)
    static boolean namesExpression(String details) {
        return EXPRESSION.matcher(details).find();
    }

    public SystemGraph link(List<ApplicationGraph> graphs, TraceSource traceSource) {
        graphs.stream().collect(Collectors.groupingBy(ApplicationGraph::service, LinkedHashMap::new,
                Collectors.mapping(ApplicationGraph::revision, Collectors.toList()))).forEach((service, revisions) -> {
                    if (revisions.size() > 1) {
                        log.warn("{} graphs of {} ({}): only the last is linked", revisions.size(), service,
                                revisions);
                    }
                });
        Map<String, ApplicationGraph> services = graphs.stream()
                .collect(Collectors.toMap(ApplicationGraph::service, Function.identity(), (a, b) -> b,
                        LinkedHashMap::new));
        Run run = new Run(services);
        run.inferStatically();
        List<List<TraceSpan>> traces = traceSource.traces(services.keySet());
        traces.forEach(run::observe);
        run.credentialFindings();
        run.audienceFindings();
        run.issuerFindings();
        run.clientTokenFindings();
        List<Flow> flows = run.networkFlows();
        SystemGraph system = new SystemGraph(SystemGraph.SCHEMA_VERSION, new ArrayList<>(services.values()),
                new ArrayList<>(run.links.values()), flows, run.observations(), run.identities.usages(), run.findings);
        if (!run.unscanned.isEmpty() || !run.leftOut.isEmpty()) {
            log.warn("Traces left out of the links: {}{}", run.leftOut, run.unscanned.isEmpty() ? ""
                    : "; services in the traces that weren't scanned (or are named otherwise in their graphs): "
                            + run.unscanned);
        }
        log.info("Linked {} services: {} links ({} observed), {} network flows, {} observations, {} identities, {}"
                + " findings from {} traces", services.size(), system.links().size(),
                system.links().stream().filter(link -> link.kind() == Edge.Kind.NETWORK_OBSERVED).count(),
                flows.size(), system.observations().size(), system.identities().size(), system.findings().size(),
                traces.size());
        return system;
    }

    private static final class Run {

        final Map<String, ApplicationGraph> services;
        final Map<String, Edge> links = new LinkedHashMap<>();
        /**
         * What each link joins, by the link's key.
         */
        final Map<String, Ends> ends = new LinkedHashMap<>();
        final Map<String, Long> linkCounts = new HashMap<>();
        final Map<String, long[]> locationCounts = new LinkedHashMap<>();
        final List<Finding> findings = new ArrayList<>();
        final Identities identities = new Identities();
        /**
         * What the traces showed that the links leave out, by why, and the services they name that weren't scanned.
         */
        final Map<String, Integer> leftOut = new TreeMap<>();
        final Set<String> unscanned = new TreeSet<>();

        /**
         * Whether both services were scanned; else the ones that weren't are noted.
         */
        private boolean scanned(String... names) {
            boolean all = true;
            for (String name : names) {
                if (!services.containsKey(name)) {
                    unscanned.add(name);
                    all = false;
                }
            }
            return all;
        }

        private void leaveOut(String why) {
            leftOut.merge(why, 1, Integer::sum);
        }

        Run(Map<String, ApplicationGraph> services) {
            this.services = services;
        }

        @Supports(Feature.FINDING_OPAQUE_CALLPATH)
        void inferStatically() {
            for (ApplicationGraph caller : services.values()) {
                for (Egress egress : caller.nodes(Egress.class)) {
                    // A host that names a service (http://vets-service, through discovery, or
                    // vets-service.default.svc.cluster.local) is that service; a bare name no scanned service has is
                    // one outside the system. Any other host is matched by its port.
                    Optional<String> named = Routes.host(egress.baseUrl())
                            .map(host -> services.containsKey(host.split("\\.", 2)[0]) ? host.split("\\.", 2)[0]
                                    : host)
                            .filter(host -> services.containsKey(host) || !host.contains(".")
                                    && !host.equals("localhost"));
                    List<String> unplaced = new ArrayList<>();
                    for (ApplicationGraph callee : services.values()) {
                        if (callee == caller || named.map(host -> !host.equals(callee.service()))
                                .orElse(!portMatches(egress, callee))) {
                            continue;
                        }
                        boolean messaging = MESSAGING.contains(egress.httpMethod());
                        if (Egress.UNKNOWN_TARGET.equals(egress.uriTemplate())) {
                            // Decision 0082: a call AuthTracer can't read the target of links to nothing. Where
                            // it goes is said when its service is known, or for a message, the services that
                            // listen to that broker.
                            if ((messaging || egress.baseUrl() != null) && callee.nodes(Ingress.class).stream()
                                    .anyMatch(ingress -> protocol(egress).equals(protocol(ingress)))) {
                                unplaced.add(callee.service());
                            }
                            continue;
                        }
                        List<Ingress> reached = callee.nodes(Ingress.class).stream()
                                .filter(ingress -> Routes.sameMethod(egress.httpMethod(), ingress.httpMethod()))
                                .filter(ingress -> messaging ? Routes.sameDestination(egress.httpMethod(),
                                        egress.uriTemplate(), ingress.route())
                                        : (Routes.reaches(egress.uriTemplate(), ingress.route())
                                                || soapAction(egress, ingress))
                                                && Routes.paramsMatch(egress.query(), ingress.params()))
                                .filter(ingress -> protocol(egress).equals(protocol(ingress)))
                                .filter(ingress -> Routes.sameNamespace(egress.query(), ingress.params()))
                                .toList();
                        // A call to /users/me lands on /users/me, not on /users/{id} next to it: Spring prefers
                        // the route that names the segment.
                        List<Ingress> exact = messaging ? List.of() : reached.stream()
                                .filter(ingress -> Routes.sameTemplate(egress.uriTemplate(), ingress.route()))
                                .toList();
                        byQuery(exact.isEmpty() ? reached : exact, egress.query()).forEach(ingress -> link(caller,
                                egress, callee, ingress, Edge.Kind.NETWORK_INFERRED));
                    }
                    if (!unplaced.isEmpty()) {
                        findings.add(new Finding(Finding.Kind.OPAQUE_CALLPATH, caller.service() + "'s "
                                + egress.client() + " " + egress.httpMethod() + " call may go to "
                                + String.join(" or ", unplaced) + ", but AuthTracer can't read what it calls there: it"
                                + " links to none of their endpoints, so what it reaches, and the checks on the way,"
                                + " are not on " + caller.service() + "'s paths", egress.callSite()));
                    }
                }
            }
        }

        /**
         * Decision 0021: a call that doesn't relay the caller's token is checked downstream as the calling service, so
         * the called endpoint's checks don't count toward what the caller's own callers need.
         */
        @Supports({Feature.FINDING_BYPASSED, Feature.FINDING_OPAQUE_CONFIG, Feature.CALL_CREDENTIALS})
        void credentialFindings() {
            for (Ends link : ends.values()) {
                ApplicationGraph caller = link.caller();
                ApplicationGraph callee = link.callee();
                Egress egress = link.egress();
                Ingress ingress = link.ingress();
                // A call no request path makes (a resource server fetching its keys) acts for no caller.
                if (Credentials.callerChecked(egress.credentials())
                        || caller.edges().stream().noneMatch(edge -> edge.to().equals(egress.id()))) {
                    continue;
                }
                List<String> checks = callee.path(ingress.id()).stream()
                        .map(edge -> callee.node(edge.to()).orElse(null))
                        .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                        .filter(location -> location.requirement().kind() != Requirement.Kind.PERMIT_ALL)
                        .map(location -> location.scope() == AuthorizationLocation.Scope.FIELD
                                ? "field check on " + location.field() : location.mechanism())
                        .distinct().toList();
                if (checks.isEmpty()) {
                    continue;
                }
                Credentials credentials = egress.credentials();
                String via = egress.credentialsVia() == null ? "" : " (" + egress.credentialsVia() + ")";
                String with = switch (credentials) {
                    case OAUTH2_CLIENT -> "its own OAuth2 client token" + via;
                    case STATIC -> "fixed credentials" + via;
                    case NONE -> "no credentials AuthTracer can see";
                    default -> "credentials AuthTracer can't read" + via;
                };
                String endpoint = callee.service() + " " + ingress.endpoint();
                findings.add(new Finding(credentials == Credentials.NONE || credentials == Credentials.UNKNOWN
                        ? Finding.Kind.OPAQUE_CONFIG : Finding.Kind.BYPASSED, caller.service() + " calls " + endpoint
                        + " with " + with + ": the checks there (" + String.join(", ", checks) + ") evaluate "
                        + caller.service() + ", not its callers, so they don't count toward what " + caller.service()
                        + "'s callers need" + (credentials == Credentials.NONE
                                ? "; the call fails unless credentials are added where AuthTracer can't see them" : ""),
                        egress.callSite()));
            }
        }

        /**
         * Decision 0075 (OAUTH-06): a relayed token passes the called service only if it names an audience that
         * service accepts, and the caller's validation guarantees only one the caller accepts. A finding when the
         * called service checks audiences and the caller's accepted ones aren't all among them; not when either
         * side has a validator the scan can't read.
         */
        @Supports(Feature.FINDING_TOKEN_REJECTED)
        void audienceFindings() {
            for (Ends link : ends.values()) {
                AuthoritySource.Jwt callee = jwt(link.callee());
                AuthoritySource.Jwt caller = jwt(link.caller());
                if (link.egress().credentials() != Credentials.RELAY || callee == null || !callee.checksAudience()
                        || !callee.unread().isEmpty() || caller != null && !caller.unread().isEmpty()
                        || caller != null && caller.checksAudience()
                                && callee.audiences().containsAll(caller.audiences())) {
                    continue;
                }
                String accepted = caller == null || !caller.checksAudience()
                        ? link.caller().service() + " accepts tokens for any audience"
                        : link.caller().service() + "'s need only name one of " + String.join(", ",
                                caller.audiences());
                findings.add(new Finding(Finding.Kind.TOKEN_REJECTED, link.caller().service()
                        + " relays its caller's token to " + link.callee().service() + " " + link.ingress().endpoint()
                        + ", which accepts only tokens for " + String.join(", ", callee.audiences()) + ", and "
                        + accepted + ": the call is rejected unless the token also names one of "
                        + String.join(", ", callee.audiences()), link.egress().callSite()));
            }
        }

        private static AuthoritySource.Jwt jwt(ApplicationGraph graph) {
            return graph.authoritySource() == null ? null : graph.authoritySource().jwt();
        }

        /**
         * Decision 0075 (SRC-19): a resource server's tokens carry only scopes a client of the authorization servers
         * that sign them can be granted. When every decoder it has fetches its keys from scanned authorization servers
         * whose clients AuthTracer reads, a check for a scope none of their clients can get denies every caller. The
         * scan has already reported the checks no token of any issuer can meet.
         */
        @Supports(Feature.FINDING_ALWAYS_DENIED)
        void issuerFindings() {
            for (ApplicationGraph server : services.values()) {
                AuthoritySource source = server.authoritySource();
                Optional<Map<String, Issuer>> issuers = issuers(server);
                if (issuers.isEmpty()) {
                    continue;
                }
                SortedSet<String> scopes = new TreeSet<>();
                issuers.get().values().forEach(issuer -> scopes.addAll(issuer.scopes()));
                Optional<AuthoritySource> narrowed = carrying(server, scopes);
                if (narrowed.isEmpty()) {
                    continue;
                }
                AuthoritySource issued = narrowed.get();
                String from = String.join(" and ", issuers.get().keySet());
                for (AuthorizationLocation location : server.nodes(AuthorizationLocation.class)) {
                    SortedSet<String> missing = issued.unmet(location.requirement());
                    if (location.mechanism().startsWith("Provided") || location.id().startsWith("location:SPLIT:")
                            || missing.isEmpty() || !source.unmet(location.requirement()).isEmpty()) {
                        continue;
                    }
                    String where = location.routePattern() != null ? location.routePattern()
                            : location.target().key();
                    findings.add(new Finding(Finding.Kind.ALWAYS_DENIED, location.mechanism() + " on " + where
                            + " in " + server.service() + " asks for " + String.join(" or ", missing) + ", which no"
                            + " token from " + from + " carries: its clients can be granted only "
                            + (scopes.isEmpty() ? "no scopes" : "the scopes " + String.join(", ", scopes))
                            + ", so it denies every caller", location.target()));
                }
            }
        }

        /**
         * What a resource server grants a token that carries only these scopes: what it grants, with each scope
         * claim's {@code SCOPE_*} narrowed to them. Empty when what it grants isn't known (a known granted set has a
         * prefix for every claim), it maps no scope claim, or another claim's values get a scope's prefix: only a
         * prefix of its own tells a scope from what else the token carries.
         */
        private static Optional<AuthoritySource> carrying(ApplicationGraph server, Set<String> scopes) {
            AuthoritySource source = server.authoritySource();
            AuthoritySource.Jwt jwt = jwt(server);
            if (jwt == null || source.granted() == null) {
                return Optional.empty();
            }
            List<AuthoritySource.ClaimAuthorities> scopeClaims = jwt.authorities().stream()
                    .filter(claim -> !Collections.disjoint(claim.claims(), SCOPE_CLAIMS)).toList();
            Set<String> prefixes = scopeClaims.stream().map(AuthoritySource.ClaimAuthorities::prefix)
                    .collect(Collectors.toSet());
            boolean shared = jwt.authorities().stream().filter(claim -> !scopeClaims.contains(claim))
                    .anyMatch(claim -> prefixes.stream().anyMatch(prefix -> claim.prefix().startsWith(prefix)
                            || prefix.startsWith(claim.prefix())));
            if (scopeClaims.isEmpty() || shared) {
                return Optional.empty();
            }
            SortedSet<String> granted = new TreeSet<>(source.granted());
            for (String prefix : prefixes) {
                granted.remove(prefix + "*");
                scopes.forEach(scope -> granted.add(prefix + scope));
            }
            return Optional.of(source.withGranted(granted));
        }

        /**
         * Decision 0075 amended: a service's own token (an OAuth2 client's, client credentials) carries the scopes
         * its client registration asks for, which the authorization server issues only when the client it
         * authenticates as can be granted them all (else {@code invalid_scope}). When the registration's token endpoint
         * is a scanned authorization server's whose clients AuthTracer reads, each call with that token is judged by
         * the checks on the called path: one that asks for a scope the token doesn't carry denies every such call. A
         * field check only hides its field, and roles aren't judged: what a token customizer adds isn't read.
         */
        @Supports(Feature.FINDING_TOKEN_REJECTED)
        void clientTokenFindings() {
            for (Ends link : ends.values()) {
                Egress egress = link.egress();
                Registration registration = egress.registration();
                if (egress.credentials() != Credentials.OAUTH2_CLIENT || registration == null
                        || registration.clientId() == null) {
                    continue;
                }
                Optional<ApplicationGraph> server = issuing(link.caller(), registration);
                if (server.isEmpty()) {
                    continue;
                }
                String caller = link.caller().service();
                String endpoint = link.callee().service() + " " + link.ingress().endpoint();
                String client = "client " + registration.clientId() + " of " + server.get().service();
                SortedSet<String> grantable = server.get().issuer().clients().get(registration.clientId());
                if (grantable == null) {
                    findings.add(new Finding(Finding.Kind.TOKEN_REJECTED, caller + " calls " + endpoint
                            + " with its own token, as " + client + ", which registers no such client: no token"
                            + " is issued, so the call fails", egress.callSite()));
                    continue;
                }
                SortedSet<String> scopes = registration.scopes();
                if (!grantable.containsAll(scopes)) {
                    findings.add(new Finding(Finding.Kind.TOKEN_REJECTED, caller + " asks for its own token, as "
                            + client + ", with the scopes " + String.join(", ", scopes) + ", but "
                            + server.get().service() + " grants that client only " + scopeList(grantable)
                            + ": the token request is refused (invalid_scope), so its call to " + endpoint
                            + " fails", egress.callSite()));
                    continue;
                }
                AuthoritySource source = link.callee().authoritySource();
                Optional<AuthoritySource> carried = carrying(link.callee(), scopes);
                if (carried.isEmpty()) {
                    continue;
                }
                List<AuthorizationLocation> checks = link.callee().path(link.ingress().id()).stream()
                        .map(edge -> link.callee().node(edge.to()).orElse(null))
                        .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                        .filter(location -> location.scope() != AuthorizationLocation.Scope.FIELD).distinct().toList();
                for (AuthorizationLocation location : checks) {
                    SortedSet<String> missing = carried.get().unmet(location.requirement());
                    if (location.mechanism().startsWith("Provided") || location.id().startsWith("location:SPLIT:")
                            || missing.isEmpty() || !source.unmet(location.requirement()).isEmpty()) {
                        continue;
                    }
                    findings.add(new Finding(Finding.Kind.TOKEN_REJECTED, caller + " calls " + endpoint
                            + " with its own token, as " + client + ", which carries " + (scopes.isEmpty()
                                    ? "no scopes" : "only " + scopeList(scopes)) + ": " + location.mechanism()
                            + " there asks for " + String.join(" or ", missing) + ", so the call is denied",
                            egress.callSite()));
                }
            }
        }

        private static String scopeList(Set<String> scopes) {
            return scopes.isEmpty() ? "no scopes" : "the scopes " + String.join(", ", scopes);
        }

        /**
         * The scanned authorization server whose clients AuthTracer reads that issues a registration's tokens: the
         * one the caller's call to the registration's token endpoint (or its issuer's OpenID configuration) links to.
         */
        private Optional<ApplicationGraph> issuing(ApplicationGraph caller, Registration registration) {
            String expected = registration.tokenUri() != null ? registration.tokenUri()
                    : registration.issuerUri() == null ? null
                    : registration.issuerUri().replaceAll("/+$", "") + "/.well-known/openid-configuration";
            if (expected == null) {
                return Optional.empty();
            }
            return ends.values().stream()
                    // IdentityProviderCalls' Egress for each registration's provider.
                    .filter(link -> link.caller() == caller && "OAuth2 client".equals(link.egress().client())
                            && link.egress().baseUrl() != null && (link.egress().baseUrl().replaceAll("/+$", "")
                                    + link.egress().uriTemplate()).equals(expected.replaceAll("/+$", ""))
                            && link.callee().issuer() != null && link.callee().issuer().unread().isEmpty())
                    .map(Ends::callee).findFirst();
        }

        /**
         * The authorization servers whose keys each of the service's JWT decoders fetches, by service, when every
         * decoder fetches them from a scanned one whose clients AuthTracer reads.
         */
        private Optional<Map<String, Issuer>> issuers(ApplicationGraph server) {
            List<Egress> decoders = server.nodes(Egress.class).stream()
                    .filter(egress -> "JwtDecoder".equals(egress.client())).toList();
            Map<String, Issuer> issuers = new TreeMap<>();
            for (Egress decoder : decoders) {
                List<ApplicationGraph> signers = ends.values().stream()
                        .filter(link -> link.caller() == server && link.egress().equals(decoder)
                                && link.callee().issuer() != null)
                        .map(Ends::callee).distinct().toList();
                if (signers.isEmpty() || signers.stream().anyMatch(signer -> !signer.issuer().unread().isEmpty())) {
                    return Optional.empty();
                }
                signers.forEach(signer -> issuers.put(signer.service(), signer.issuer()));
            }
            return issuers.isEmpty() ? Optional.empty() : Optional.of(issuers);
        }

        /**
         * A link's two ends.
         */
        private record Ends(ApplicationGraph caller, Egress egress, ApplicationGraph callee, Ingress ingress) {
        }

        /**
         * A GraphQL client call names an operation, which only a GraphQL Ingress answers (decision 0031); a gRPC
         * stub call an rpc, which only a gRPC Ingress serves (decision 0032).
         */
        private static String protocol(Egress egress) {
            if (MESSAGING.contains(egress.httpMethod())) {
                // Decision 0044: a message sent to a topic reaches that topic's listeners.
                return egress.httpMethod();
            }
            return switch (egress.client()) {
                case "GraphQlClient" -> "graphql";
                case "gRPC" -> "grpc";
                case "RSocketRequester" -> "rsocket";
                case "WebServiceTemplate" -> "soap";
                case null, default -> "http";
            };
        }

        private static String protocol(Ingress ingress) {
            return MESSAGING.contains(ingress.httpMethod()) ? ingress.httpMethod() : ingress.graphQlOperation()
                    ? "graphql" : "GRPC".equals(ingress.httpMethod()) ? "grpc"
                            : "RSOCKET".equals(ingress.httpMethod()) ? "rsocket"
                                    : "WEBSOCKET".equals(ingress.httpMethod()) ? "websocket"
                                            : "SOAP".equals(ingress.httpMethod()) ? "soap" : "http";
        }

        /**
         * Decision 0056: a SOAP call that names an action reaches the operation mapped to it, which Spring WS takes
         * when no operation is mapped to its payload's root (an exact match on that root wins over it).
         */
        private static boolean soapAction(Egress egress, Ingress ingress) {
            return "SOAP".equals(ingress.httpMethod()) && Routes.condition(egress.query(), Routes.SOAP_ACTION)
                    .filter(ingress.route()::equals).isPresent();
        }

        /**
         * Whether the call's port is one the service listens on: its {@code server.port}, Spring Boot's 8080 when it
         * sets none, or another it opens. A call to {@code https://api.example.com} (443) is none of the system's.
         */
        private static boolean portMatches(Egress egress, ApplicationGraph callee) {
            if (egress.baseUrl() == null) {
                return true;
            }
            int listening = callee.port() == null ? DEFAULT_PORT : callee.port();
            return Routes.port(egress.baseUrl()).map(port -> port == listening
                    || callee.additionalPorts().contains(port)).orElse(true);
        }

        @Supports(Feature.TRACE_OBSERVATIONS)
        void observe(List<TraceSpan> trace) {
            Map<String, TraceSpan> byId = new HashMap<>();
            Map<String, List<TraceSpan>> children = new HashMap<>();
            for (TraceSpan span : trace) {
                byId.put(span.id(), span);
                if (span.parentId() != null) {
                    children.computeIfAbsent(span.parentId(), id -> new ArrayList<>()).add(span);
                }
            }
            for (TraceSpan span : trace) {
                if (span.isServer() || span.isConsumer()) {
                    observeChecks(span, byId, children);
                }
                if (span.isProducer()) {
                    for (TraceSpan consumer : children.getOrDefault(span.id(), List.of())) {
                        if (consumer.isConsumer()) {
                            observeMessage(span, consumer, byId, children);
                        }
                    }
                }
                if (!span.isClient()) {
                    continue;
                }
                for (TraceSpan server : children.getOrDefault(span.id(), List.of())) {
                    if (server.isServer()) {
                        observeCall(span, server, byId, children);
                    }
                }
            }
        }

        @Supports({Feature.FINDING_UNMATCHED_CALL, Feature.TRACE_OBSERVATIONS})
        private void observeCall(TraceSpan client, TraceSpan server, Map<String, TraceSpan> byId,
                Map<String, List<TraceSpan>> children) {
            if (!scanned(client.service(), server.service())) {
                leaveOut("calls to or from a service not scanned");
                return;
            }
            ApplicationGraph caller = services.get(client.service());
            ApplicationGraph callee = services.get(server.service());
            List<String> operations = graphQlOperations(server, children);
            List<Ingress> ingresses = ingresses(callee, server, operations, query(server, byId));
            List<Egress> egresses = egresses(caller, client, enclosingServer(client, byId), operations, byId,
                    children);
            if (ingresses.size() > 1 && !egresses.isEmpty()) {
                // Endpoints told apart by what the trace doesn't record: the static links stand for the call.
                log.debug("{} called {} on one of {}", client.service(), server.service(), ingresses);
                leaveOut("calls the trace can't tell between several endpoints (the static links stand)");
                return;
            }
            Optional<Ingress> ingress = ingresses.stream().findFirst();
            if (ingress.isEmpty() || egresses.isEmpty()) {
                findings.add(new Finding(Finding.Kind.UNMATCHED_CALL, client.service() + " called "
                        + server.service() + " " + client.tag(METHOD_TAGS).orElse("?") + " "
                        + client.tag("uri").or(() -> client.tag(CLIENT_URL_TAGS)).orElse("?")
                        + ", which matches no static "
                        + (egresses.isEmpty() ? "egress in " + client.service() : "ingress in " + server.service()),
                        CodeRef.ofClass(client.service())));
                return;
            }
            for (Egress egress : egresses) {
                String key = link(caller, egress, callee, ingress.get(), Edge.Kind.NETWORK_OBSERVED);
                linkCounts.merge(key, 1L, Long::sum);
            }
        }

        /**
         * A message one service sent and another's listener received: Spring Kafka's and Spring AMQP's observations
         * make the send a producer span and each delivery a consumer span under it (checked against Spring Boot 4.1.1
         * services with observations on), as Spring JMS's do (Micrometer's {@code SenderContext} and
         * {@code ReceiverContext}, the trace carried in the message's properties). The send is the Egress to that
         * topic, queue or destination, the listener the Ingress.
         */
        @Supports({Feature.FINDING_UNMATCHED_CALL, Feature.TRACE_OBSERVATIONS})
        private void observeMessage(TraceSpan producer, TraceSpan consumer, Map<String, TraceSpan> byId,
                Map<String, List<TraceSpan>> children) {
            ApplicationGraph caller = services.get(producer.service());
            ApplicationGraph callee = services.get(consumer.service());
            Optional<String> kind = messaging(producer).or(() -> messaging(consumer));
            if (kind.isEmpty()) {
                return;
            }
            if (!scanned(producer.service(), consumer.service())) {
                leaveOut("messages to or from a service not scanned");
                return;
            }
            Optional<String> sent = sentTo(kind.get(), producer);
            List<Ingress> ingresses = ingresses(callee, consumer, List.of(), null);
            List<Egress> egresses = narrow(caller, caller.nodes(Egress.class).stream()
                    .filter(egress -> egress.httpMethod().equals(kind.get()))
                    .filter(egress -> egress.uriTemplate().equals(sent.orElse(Egress.UNKNOWN_TARGET)))
                    .toList(), enclosingServer(producer, byId), byId, children);
            if (ingresses.size() > 1 && !egresses.isEmpty()) {
                // Listeners told apart by what the trace doesn't record (a payload type): the static links stand.
                return;
            }
            if (ingresses.isEmpty() || egresses.isEmpty()) {
                findings.add(new Finding(Finding.Kind.UNMATCHED_CALL, producer.service() + " sent "
                        + consumer.service() + " a " + kind.get() + " message on "
                        + sent.or(() -> receivedFrom(consumer)).orElse("?") + ", which matches no static "
                        + (egresses.isEmpty() ? "egress in " + producer.service()
                                : "listener in " + consumer.service()), CodeRef.ofClass(producer.service())));
                return;
            }
            for (Egress egress : egresses) {
                String key = link(caller, egress, callee, ingresses.getFirst(), Edge.Kind.NETWORK_OBSERVED);
                linkCounts.merge(key, 1L, Long::sum);
            }
        }

        /**
         * A messaging span's broker, as the Egress and Ingress name it: Kafka's spans say {@code messaging.system};
         * Spring AMQP's (4.1.1) don't, but their other tags name RabbitMQ. Spring JMS's (7.0.9, with Micrometer
         * 1.17.1's {@code jakarta9} conventions, {@code jms.message.publish} and {@code jms.message.process}) don't
         * either, but only they say whether the destination is temporary.
         */
        private static Optional<String> messaging(TraceSpan span) {
            String system = span.tag("messaging.system").orElse("");
            if (system.equals("kafka")) {
                return Optional.of("KAFKA");
            }
            if (system.equals("rabbitmq") || span.tags().keySet().stream()
                    .anyMatch(tag -> tag.startsWith("messaging.rabbitmq.") || tag.startsWith("spring.rabbit."))) {
                return Optional.of("RABBIT");
            }
            if (span.tags().containsKey(JMS_TEMPORARY)) {
                return Optional.of("JMS");
            }
            return Optional.empty();
        }

        /**
         * Where a send went, as its Egress names it: the topic or destination; for RabbitMQ the routing key, which
         * the default exchange ({@code ""}) routes to the queue of that name. A named exchange's bindings aren't in
         * the trace, nor is a JMS destination Micrometer couldn't name ({@code unknown}).
         */
        private static Optional<String> sentTo(String kind, TraceSpan producer) {
            Optional<String> destination = Optional.ofNullable(producer.tags().get("messaging.destination.name"));
            if (kind.equals("JMS")) {
                return destination.filter(name -> !name.isBlank() && !name.equals(JMS_UNKNOWN));
            }
            if (!kind.equals("RABBIT")) {
                return destination.filter(name -> !name.isBlank());
            }
            return destination.filter(String::isEmpty).flatMap(exchange ->
                    producer.tag("messaging.rabbitmq.destination.routing_key"));
        }

        /**
         * The topic, queue or destination a listener received from: Spring Kafka's consumer spans call it the source.
         */
        private static Optional<String> receivedFrom(TraceSpan consumer) {
            Optional<String> from = consumer.tag("messaging.source.name", "messaging.destination.name");
            return consumer.tags().containsKey(JMS_TEMPORARY) ? from.filter(name -> !name.equals(JMS_UNKNOWN)) : from;
        }

        private String link(ApplicationGraph caller, Egress egress, ApplicationGraph callee, Ingress ingress,
                Edge.Kind kind) {
            String from = SystemGraph.qualify(caller.service(), egress.id());
            String to = SystemGraph.qualify(callee.service(), ingress.id());
            String key = Observation.linkSubject(from, to);
            ends.putIfAbsent(key, new Ends(caller, egress, callee, ingress));
            Edge existing = links.get(key);
            if (existing == null || existing.kind() == Edge.Kind.NETWORK_INFERRED) {
                links.put(key, new Edge(from, to, kind, null, 0, List.of(), true));
            }
            return key;
        }

        /**
         * The callee's endpoint, when the trace says which one it was; see {@link #ingresses}.
         */
        private static Optional<Ingress> ingress(ApplicationGraph graph, TraceSpan server, List<String> operations,
                String query) {
            List<Ingress> ingresses = ingresses(graph, server, operations, query);
            return ingresses.size() == 1 ? Optional.of(ingresses.getFirst()) : Optional.empty();
        }

        /**
         * The endpoints a server span may have served: by the span's route template, or for requests denied before
         * routing, the URL path. Of several, the ones Spring would pick: a mapping for the request's method over one
         * for any method, and one whose params the query meets over one without params. More than one when the trace
         * can't tell them apart.
         *
         * @param operations the GraphQL operations the server span ran, e.g. {@code QUERY person}
         * @param query the request's query string, {@code ""} for none, {@code null} when the trace doesn't record it
         */
        private static List<Ingress> ingresses(ApplicationGraph graph, TraceSpan server, List<String> operations,
                String query) {
            if (server.isConsumer()) {
                // A message's listener: of the broker's kind, on the topic or queue it came from.
                Optional<String> kind = messaging(server);
                Optional<String> from = receivedFrom(server);
                return kind.isEmpty() || from.isEmpty() ? List.of() : graph.nodes(Ingress.class).stream()
                        .filter(ingress -> ingress.httpMethod().equals(kind.get())
                                && Routes.sameDestination(kind.get(), from.get(), ingress.route()))
                        .toList();
            }
            if (!operations.isEmpty()) {
                return graph.nodes(Ingress.class).stream()
                        .filter(ingress -> operations.contains(ingress.httpMethod() + " " + ingress.route()))
                        .limit(1).toList();
            }
            Optional<String> rpc = rpc(server);
            if (rpc.isPresent()) {
                return graph.nodes(Ingress.class).stream().filter(ingress -> "GRPC".equals(ingress.httpMethod())
                        && ingress.route().equals(rpc.get())).limit(1).toList();
            }
            String method = server.tag(METHOD_TAGS).orElse("*");
            Optional<String> route = server.tag("uri", "http.route").filter(uri -> uri.startsWith("/"))
                    .filter(uri -> !uri.equals("/**"));
            List<Ingress> ingresses = graph.nodes(Ingress.class);
            if (route.isPresent()) {
                List<Ingress> byRoute = mostSpecific(ingresses.stream()
                        .filter(ingress -> Routes.sameMethod(method, ingress.httpMethod()))
                        .filter(ingress -> Routes.sameTemplate(route.get(), ingress.route()))
                        .toList(), method, query);
                if (!byRoute.isEmpty()) {
                    return byRoute;
                }
            }
            return server.tag("http.url", "url.path", "http.target").map(Routes::path)
                    .map(path -> mostSpecific(ingresses.stream()
                            .filter(ingress -> Routes.sameMethod(method, ingress.httpMethod()))
                            .filter(ingress -> Routes.matchesPath(ingress.route(), path))
                            .toList(), method, query))
                    .orElse(List.of());
        }

        private static List<Ingress> mostSpecific(List<Ingress> candidates, String method, String query) {
            List<Ingress> matching = candidates.stream()
                    .filter(ingress -> Routes.paramsMatch(query, ingress.params())).toList();
            List<Ingress> sameMethod = matching.stream()
                    .filter(ingress -> ingress.httpMethod().equalsIgnoreCase(method)).toList();
            if (!sameMethod.isEmpty()) {
                matching = sameMethod;
            }
            return byQuery(matching, query);
        }

        /**
         * Of the endpoints whose params a known query meets, the one Spring routes it to when it is the only one that
         * names request parameters: a mapping with them is more specific than one without. A header or media type
         * the request may or may not have sent tells nothing apart.
         */
        private static List<Ingress> byQuery(List<Ingress> candidates, String query) {
            if (query == null || candidates.size() < 2) {
                return candidates;
            }
            List<Ingress> conditioned = candidates.stream()
                    .filter(ingress -> Routes.namesParameters(ingress.params())).toList();
            return conditioned.size() == 1 ? conditioned : candidates;
        }

        /**
         * The query string of the request a server span served: its own tags when they hold it (OpenTelemetry's
         * {@code url.query}, or the target of older versions), else the URL of the client call it answered.
         * Micrometer's server spans record the path only.
         *
         * @return {@code ""} for none, {@code null} when unknown
         */
        private static String query(TraceSpan server, Map<String, TraceSpan> byId) {
            Optional<String> own = server.tag("url.query")
                    .or(() -> server.tag("http.target").filter(target -> target.contains("?"))
                            .map(target -> target.substring(target.indexOf('?') + 1)));
            if (own.isPresent()) {
                return own.get();
            }
            TraceSpan parent = server.parentId() == null ? null : byId.get(server.parentId());
            return parent != null && parent.isClient() ? clientQuery(parent) : null;
        }

        private static String clientQuery(TraceSpan client) {
            return client.tag(CLIENT_URL_TAGS).map(url -> {
                int start = url.indexOf('?');
                if (start < 0) {
                    return "";
                }
                int fragment = url.indexOf('#', start);
                return url.substring(start + 1, fragment < 0 ? url.length() : fragment);
            }).orElse(null);
        }

        /**
         * Egress matching the client span; when several do, the ones on the path of the request being served.
         *
         * @param operations the GraphQL operations the call ran in the called service, e.g. {@code QUERY person}
         */
        private static List<Egress> egresses(ApplicationGraph graph, TraceSpan client, Optional<TraceSpan> serving,
                List<String> operations, Map<String, TraceSpan> byId, Map<String, List<TraceSpan>> children) {
            Optional<String> rpc = rpc(client);
            if (rpc.isPresent()) {
                return graph.nodes(Egress.class).stream().filter(egress -> "GRPC".equals(egress.httpMethod())
                        && egress.uriTemplate().equals(rpc.get())).toList();
            }
            if (!operations.isEmpty()) {
                // A GraphQL call is POST /graphql on the wire: the client call is the one sending that operation.
                List<Egress> candidates = graph.nodes(Egress.class).stream()
                        .filter(egress -> "GraphQlClient".equals(egress.client()))
                        .filter(egress -> operations.stream().anyMatch(operation -> operation.endsWith(" "
                                + egress.uriTemplate()) && Routes.sameMethod(egress.httpMethod(),
                                        operation.substring(0, operation.indexOf(' ')))))
                        .toList();
                return narrow(graph, candidates, serving, byId, children);
            }
            String method = client.tag(METHOD_TAGS).orElse("*");
            Optional<String> template = client.tag("uri").filter(uri -> uri.startsWith("/"));
            Optional<String> path = client.tag(CLIENT_URL_TAGS).map(Routes::path);
            List<Egress> candidates = graph.nodes(Egress.class).stream()
                    .filter(egress -> Routes.sameMethod(method, egress.httpMethod()))
                    .filter(egress -> template.map(t -> Routes.reaches(egress.uriTemplate(), t))
                            .orElseGet(() -> path.map(p -> Routes.matchesPath(egress.uriTemplate(), p)).orElse(false)))
                    .toList();
            return narrow(graph, candidates, serving, byId, children);
        }

        /**
         * Of several Egress the call could be, the ones on the path of the request the calling service was serving.
         */
        private static List<Egress> narrow(ApplicationGraph graph, List<Egress> candidates,
                Optional<TraceSpan> serving, Map<String, TraceSpan> byId, Map<String, List<TraceSpan>> children) {
            if (candidates.size() < 2 || serving.isEmpty()) {
                return candidates;
            }
            Optional<Ingress> servingIngress = ingress(graph, serving.get(), graphQlOperations(serving.get(),
                    children), query(serving.get(), byId));
            if (servingIngress.isEmpty()) {
                return candidates;
            }
            Set<String> onPath = graph.path(servingIngress.get().id()).stream().map(Edge::to)
                    .collect(Collectors.toSet());
            List<Egress> narrowed = candidates.stream().filter(egress -> onPath.contains(egress.id())).toList();
            return narrowed.isEmpty() ? candidates : narrowed;
        }

        /**
         * Decision 0031: the GraphQL operations a server span ran, from Spring for GraphQL's observations below it:
         * the operation's type ({@code graphql.operation.type}) and the root fields its data fetchers resolved
         * ({@code graphql.field.path} {@code /person}), e.g. {@code QUERY person}.
         */
        private static List<String> graphQlOperations(TraceSpan server, Map<String, List<TraceSpan>> children) {
            List<TraceSpan> below = local(server, children);
            String type = below.stream().map(span -> span.tag("graphql.operation.type")).flatMap(Optional::stream)
                    .findFirst().orElse("query").toUpperCase(Locale.ROOT);
            return below.stream().map(span -> span.tag("graphql.field.path")).flatMap(Optional::stream)
                    .filter(path -> path.lastIndexOf('/') == 0 && path.length() > 1)
                    .map(path -> type + " " + path.substring(1)).distinct().toList();
        }

        /**
         * Decision 0032: a gRPC span's full method name, from the {@code rpc.service} and {@code rpc.method} tags
         * that OpenTelemetry's and Micrometer's gRPC instrumentation both set.
         */
        private static Optional<String> rpc(TraceSpan span) {
            Optional<String> service = span.tag("rpc.service");
            Optional<String> method = span.tag("rpc.method");
            return service.isPresent() && method.isPresent() && !"http".equals(span.tag("rpc.system").orElse(null))
                    ? Optional.of(service.get() + "/" + method.get()) : Optional.empty();
        }

        private static Optional<TraceSpan> enclosingServer(TraceSpan span, Map<String, TraceSpan> byId) {
            TraceSpan current = span.parentId() == null ? null : byId.get(span.parentId());
            while (current != null) {
                if (current.isServer() && span.service().equals(current.service())) {
                    return Optional.of(current);
                }
                current = current.parentId() == null ? null : byId.get(current.parentId());
            }
            return Optional.empty();
        }

        /**
         * Matches the authorization decisions Spring Security recorded while serving a request to the Locations on
         * that Ingress's static path.
         */
        @Supports({Feature.FINDING_RUNTIME_ONLY_CHECK, Feature.IDENTITIES, Feature.TRACE_OBSERVATIONS})
        private void observeChecks(TraceSpan server, Map<String, TraceSpan> byId,
                Map<String, List<TraceSpan>> children) {
            if (!scanned(server.service())) {
                return;
            }
            ApplicationGraph graph = services.get(server.service());
            // Of endpoints the trace can't tell apart, none: their checks differ, and a guess would mismatch them.
            Optional<Ingress> ingress = ingress(graph, server, graphQlOperations(server, children),
                    query(server, byId));
            if (ingress.isEmpty()) {
                leaveOut("requests whose checks aren't compared: they match no single endpoint");
                return;
            }
            List<AuthorizationLocation> path = graph.path(ingress.get().id()).stream()
                    .map(edge -> graph.node(edge.to()).orElse(null))
                    .filter(AuthorizationLocation.class::isInstance)
                    .map(AuthorizationLocation.class::cast)
                    .toList();
            Set<String> matched = new HashSet<>();
            List<TraceSpan> decisions = decisions(server, children);
            // A message has no caller: whatever a listener authenticates as is no test user's request.
            Optional<Identities.Identity> identity = server.isServer() ? identities.request(decisions,
                    graph.service() + " " + ingress.get().endpoint()) : Optional.empty();
            for (TraceSpan decision : decisions) {
                boolean granted = decision.tag(DECISION).map("true"::equals).orElse(false);
                String details = decision.tag(DECISION_DETAILS).orElse("");
                List<AuthorizationLocation> candidates = path.stream()
                        .filter(candidate -> scopeMatches(decision.name(), candidate.scope()))
                        .filter(candidate -> decisionMatches(details, candidate.requirement(),
                                graph.authoritySource().roleHierarchy()))
                        .toList();
                // Prefer a Location not yet seen in this request; field checks repeat once per returned element.
                Optional<AuthorizationLocation> location = candidates.stream()
                        .filter(candidate -> !matched.contains(candidate.id())).findFirst()
                        .or(() -> candidates.stream().findFirst());
                identity.ifPresent(found -> found.check(granted, details,
                        location.map(AuthorizationLocation::requirement)));
                if (location.isEmpty()) {
                    findings.add(new Finding(Finding.Kind.RUNTIME_ONLY_CHECK, "Spring Security evaluated "
                            + details + " (" + decision.name() + ") for " + graph.service() + " "
                            + ingress.get().endpoint()
                            + ", but the static graph has no matching Location on that path",
                            ingress.get().handler()));
                    continue;
                }
                matched.add(location.get().id());
                long[] counts = locationCounts.computeIfAbsent(
                        SystemGraph.qualify(graph.service(), location.get().id()), id -> new long[2]);
                counts[granted ? 0 : 1]++;
            }
        }

        /**
         * Authorization spans under a server span, in time order, not descending into outgoing calls.
         */
        private static List<TraceSpan> decisions(TraceSpan server, Map<String, List<TraceSpan>> children) {
            return local(server, children).stream()
                    .filter(span -> AUTHORIZE_REQUEST.contains(span.name()) || AUTHORIZE_METHOD.equals(span.name()))
                    .filter(span -> span.tag(DECISION).isPresent())
                    .sorted(Comparator.comparingLong(TraceSpan::timestamp)).toList();
        }

        /**
         * The spans a server (or consumer) span's service made while serving it, breadth first: not the calls it made
         * to other services (client spans) or the messages it sent (producer spans), nor what those served.
         */
        private static List<TraceSpan> local(TraceSpan server, Map<String, List<TraceSpan>> children) {
            List<TraceSpan> below = new ArrayList<>();
            Deque<TraceSpan> queue = new ArrayDeque<>(children.getOrDefault(server.id(), List.of()));
            while (!queue.isEmpty()) {
                TraceSpan span = queue.removeFirst();
                if (span.isClient() || span.isServer() || span.isProducer() || span.isConsumer()) {
                    continue;
                }
                below.add(span);
                queue.addAll(children.getOrDefault(span.id(), List.of()));
            }
            return below;
        }

        private static boolean scopeMatches(String spanName, AuthorizationLocation.Scope scope) {
            return AUTHORIZE_REQUEST.contains(spanName) == (scope == AuthorizationLocation.Scope.HTTP_REQUEST);
        }

        /**
         * @param roleHierarchy the service's RoleHierarchy, {@code null} for none: Spring names the roles a check
         *        was configured with, the graph also lists the roles that imply them
         */
        @Supports(Feature.TRACE_OBSERVATIONS)
        static boolean decisionMatches(String details, Requirement requirement,
                Map<String, ? extends Set<String>> roleHierarchy) {
            Matcher expression = EXPRESSION.matcher(details);
            if (expression.find()) {
                return requirement.expression() != null
                        && compact(requirement.expression()).equals(compact(expression.group(1)));
            }
            if (AUTHORITIES.matcher(details).find()) {
                return widened(askedAuthorities(details), roleHierarchy).equals(requirement.authorities());
            }
            return switch (requirement.kind()) {
                case AUTHENTICATED, FULLY_AUTHENTICATED, REMEMBER_ME, ANONYMOUS, PERMIT_ALL, DENY_ALL -> true;
                default -> false;
            };
        }

        /**
         * The authorities plus every role that implies one of them.
         */
        private static Set<String> widened(Set<String> authorities, Map<String, ? extends Set<String>> roleHierarchy) {
            Set<String> widened = new TreeSet<>(authorities);
            boolean grew = roleHierarchy != null;
            while (grew) {
                grew = false;
                for (Map.Entry<String, ? extends Set<String>> role : roleHierarchy.entrySet()) {
                    if (!widened.contains(role.getKey())
                            && role.getValue().stream().anyMatch(widened::contains)) {
                        grew = widened.add(role.getKey());
                    }
                }
            }
            return widened;
        }

        private static String compact(String expression) {
            return expression.replaceAll("\\s+", "").replace('"', '\'');
        }

        /**
         * Fields that cross each link: the caller's response type matched to the callee's by JSON name; and, decision
         * 0090, a message's, the listener's parameter type matched to the type the sender sends, as the brokers'
         * JSON converters write and read them.
         */
        @Supports(Feature.FIELD_LINEAGE)
        List<Flow> networkFlows() {
            List<Flow> flows = new ArrayList<>();
            for (Ends link : ends.values()) {
                String path = SystemGraph.qualify(link.caller().service(), link.egress().id());
                if (link.egress().response() != null && link.ingress().response() != null) {
                    matchFields(path, link.caller(), link.egress().response().type(), link.callee(),
                            link.ingress().response().type(), flows, 0, new HashSet<>());
                }
                if (link.egress().request() != null && link.ingress().request() != null) {
                    matchFields(path, link.callee(), link.ingress().request().type(), link.caller(),
                            link.egress().request().type(), flows, 0, new HashSet<>());
                }
            }
            return flows;
        }

        /**
         * @param matched the pairs of types already matched on this link: a type that holds itself (a manager, a
         *        mentor) adds nothing the second time
         */
        private static void matchFields(String path, ApplicationGraph caller, String callerType,
                ApplicationGraph callee, String calleeType, List<Flow> flows, int depth, Set<String> matched) {
            if (depth > MAX_FIELD_DEPTH || !matched.add(callerType + " " + calleeType)) {
                return;
            }
            Map<String, Field> remote = callee.nodes(Field.class).stream()
                    .filter(field -> field.owner().equals(calleeType))
                    .collect(Collectors.toMap(Field::jsonName, Function.identity(), (a, b) -> a));
            for (Field local : caller.nodes(Field.class)) {
                if (!local.owner().equals(callerType)) {
                    continue;
                }
                Field source = remote.get(local.jsonName());
                if (source == null) {
                    continue;
                }
                flows.add(new Flow(path, SystemGraph.qualify(callee.service(), source.id()),
                        SystemGraph.qualify(caller.service(), local.id()), FieldSource.DIRECT, Flow.Kind.NETWORK));
                matchFields(path, caller, Field.held(local.javaType()), callee, Field.held(source.javaType()), flows,
                        depth + 1, matched);
            }
        }

        @Supports(Feature.TRACE_OBSERVATIONS)
        List<Observation> observations() {
            List<Observation> observations = new ArrayList<>();
            locationCounts.forEach((subject, counts) -> observations.add(new Observation(subject,
                    Observation.Kind.LOCATION, counts[0] + counts[1], counts[0], counts[1])));
            linkCounts.forEach((subject, count) -> observations.add(new Observation(subject, Observation.Kind.LINK,
                    count, 0, 0)));
            return observations;
        }
    }
}
