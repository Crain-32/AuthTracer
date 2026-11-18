package dev.crain.authtracer.annotations;

import java.util.List;

/**
 * What AuthTracer gives the people who use it: each kind of thing of value in its response, from one kind of entry
 * point in a scanned graph to one view of the UI. Code names the features it is needed for with {@link Supports}, and
 * {@code guide/codebase/features.md} lists the code of each, generated from those annotations.
 * <p>
 * A feature also relies on the features it {@link #requires()}: the code a feature needs is its own and theirs.
 * Constants are declared after the features they require.
 */
public enum Feature {

    // The graph of one service, and what goes into building it.

    APPLICATION_GRAPH(Area.GRAPH, "One service's authorization graph as a scan writes it: its entry points, checks,"
            + " calls, fields and findings, in JSON that compares cleanly between revisions"),
    PROJECT_BUILDS(Area.GRAPH, "Scanning a Gradle or Maven project by its directory: its classes, libraries and"
            + " configuration, compiled first when needed", APPLICATION_GRAPH),
    BUILT_ARTIFACTS(Area.GRAPH, "Scanning a built Spring Boot jar or war: unpacked, never run, into its classes,"
            + " libraries and configuration, its service and revision read from what the build recorded",
            APPLICATION_GRAPH),
    PROVIDED_FACTS(Area.GRAPH, "What people tell the scan in authtracer.yaml and the organisation's facts file:"
            + " sensitive fields, declassified ones, reviewed hand-rolled checks, requirements enforced outside the"
            + " code; the organisation's facts win", APPLICATION_GRAPH),
    AUTHORITY_SOURCE(Area.GRAPH, "Where a service's authorities come from (JWT claims, token introspection,"
            + " UserDetails, a login's identity provider, WS-Security, a filter's own code) and how fresh they are, and"
            + " the checks that read a live source of their own", APPLICATION_GRAPH),
    CALL_PATHS(Area.GRAPH, "Each entry point's steps in the order they run: filters, rules, interceptors, then what"
            + " the handler reaches through proxies, other threads and branches only some returns take",
            APPLICATION_GRAPH),

    // Every way in.

    HTTP_ENDPOINTS(Area.ENTRY_POINTS, "HTTP endpoints: annotated controllers, functional routes, JAX-RS resources,"
            + " servlets, SOAP operations and the repositories Spring Data REST exports", CALL_PATHS),
    GRAPHQL_OPERATIONS(Area.ENTRY_POINTS, "GraphQL queries, mutations, subscriptions and field resolvers, over HTTP"
            + " and WebSocket, with the fields the schema has", CALL_PATHS),
    GRPC_METHODS(Area.ENTRY_POINTS, "gRPC service methods, on their own server or through the servlet container",
            CALL_PATHS),
    MESSAGE_LISTENERS(Area.ENTRY_POINTS, "Kafka, RabbitMQ and JMS listeners and Spring Cloud Stream functions, which"
            + " run without a caller", CALL_PATHS),
    WEBSOCKET_MESSAGES(Area.ENTRY_POINTS, "STOMP messages and subscriptions (with what the application pushes to"
            + " their destinations) and plain WebSocket handlers, behind their handshake", CALL_PATHS),
    RSOCKET_ROUTES(Area.ENTRY_POINTS, "RSocket routes, behind their connection's setup", CALL_PATHS),
    SCHEDULED_TASKS(Area.ENTRY_POINTS, "Scheduled tasks and the event listeners they publish to, which run without"
            + " a caller", CALL_PATHS),
    LIBRARY_ENDPOINTS(Area.ENTRY_POINTS, "Endpoints a library serves: Actuator, an authorization server, a resource"
            + " server's metadata, a config server, a Eureka server, the H2 console and other library servlets, API"
            + " docs, GraphiQL, gRPC reflection and health", CALL_PATHS),
    GATEWAY_ROUTES(Area.ENTRY_POINTS, "Spring Cloud Gateway routes, forwarded on after the gateway's own rules",
            CALL_PATHS),

    // Every check, and what it asks for.

    REQUIREMENTS(Area.CHECKS, "What each check asks for, in one normalized form: SpEL reduced to authorities, role"
            + " prefixes, the role hierarchy, additional factors, what callers who haven't signed in hold, and what an"
            + " expression reads besides authorities (method parameters and what the request binds into them, token"
            + " claims)", APPLICATION_GRAPH),
    REQUEST_RULES(Area.CHECKS, "The filter chain's rules on each entry point, in the order Spring tries them: the"
            + " Java, Kotlin and XML configuration, Boot's default chains, and the gRPC, message and RSocket rules",
            CALL_PATHS, REQUIREMENTS),
    METHOD_SECURITY(Area.CHECKS, "Method checks (@PreAuthorize and its kin, @Secured, JSR-250, XML, custom advisors"
            + " and pointcuts) where a Spring proxy applies them, where a call skips the proxy, Jersey's @RolesAllowed,"
            + " and Spring Data queries that filter rows by the caller", CALL_PATHS, REQUIREMENTS),
    CUSTOM_DECISIONS(Area.CHECKS, "Checks decided by application code (custom AuthorizationManagers, SpEL beans,"
            + " PermissionEvaluators, checks the code makes itself), shown with what that code reads and calls",
            REQUIREMENTS, CALL_PATHS),
    STRUCTURE_RULES(Area.CHECKS, "Checks of an authorization library AuthTracer doesn't know, described by their"
            + " shape in authtracer.yaml: an annotation, or a call to one of its methods, and the requirement it"
            + " enforces, filled from the annotation's attributes or the call's arguments", PROVIDED_FACTS,
            REQUIREMENTS, CALL_PATHS),

    // Every field of a response, and where its value comes from.

    RESPONSE_FIELDS(Area.FIELDS, "The fields of each response and message, as JSON writes them (Jackson's"
            + " visibility, @JsonView, GraphQL's schema)", APPLICATION_GRAPH),
    FIELD_LINEAGE(Area.FIELDS, "Where each field's value comes from (Direct, Complex, Computed, Masked), inside a"
            + " service and across the calls and messages between services", RESPONSE_FIELDS, CALL_PATHS),
    FIELD_CHECKS(Area.FIELDS, "Checks on single fields of a response, and what a denied caller gets in their place",
            RESPONSE_FIELDS, METHOD_SECURITY),
    VIEW_FIELDS(Area.FIELDS, "Server-rendered views (Thymeleaf, JSP, FreeMarker): the model fields a page shows, and"
            + " the guards around them", RESPONSE_FIELDS, REQUEST_RULES),

    // Every call out.

    SERVICE_CALLS(Area.CALLS, "Calls to other services: RestClient, WebClient, RestTemplate, HTTP interfaces,"
            + " OpenFeign, the JDK's HttpClient, gRPC stubs, GraphQL and SOAP clients, RSocket requesters",
            CALL_PATHS),
    MESSAGE_SENDS(Area.CALLS, "Messages sent to topics and queues (Kafka, RabbitMQ, JMS, Stream bridges), with"
            + " what they carry", CALL_PATHS),
    INFRASTRUCTURE_CALLS(Area.CALLS, "Calls a service makes off its request paths: to its authorization server"
            + " (issuer, keys, token introspection, token endpoint), its config server and Eureka", APPLICATION_GRAPH),
    CALL_CREDENTIALS(Area.CALLS, "What each call authenticates with (the caller's relayed token, the service's own"
            + " client token, fixed credentials, nothing), which decides whose checks the called service makes; and"
            + " the clients an authorization server issues tokens to, with the scopes each can be granted",
            SERVICE_CALLS),

    // Several services as one system.

    SYSTEM_GRAPH(Area.SYSTEM, "Services linked into one system: each call matched to the endpoint, listener or"
            + " method it reaches, and the fields that travel with it", SERVICE_CALLS, MESSAGE_SENDS),
    TRACE_OBSERVATIONS(Area.SYSTEM, "Links confirmed from Zipkin traces, with how often each was called and how often"
            + " each check granted or denied", SYSTEM_GRAPH),
    IDENTITIES(Area.SYSTEM, "The identities traces showed: what each was granted, what its requests needed, and the"
            + " grants it never used", TRACE_OBSERVATIONS),

    // Findings: what a person should look at. One per finding kind.

    FINDING_NOT_ENFORCED(Area.FINDINGS, "NOT_ENFORCED: something that looks like a check isn't enforced, e.g. method"
            + " security is not enabled, or a filter chain is for the web stack the application doesn't run",
            METHOD_SECURITY, REQUEST_RULES),
    FINDING_BYPASSED(Area.FINDINGS, "BYPASSED: an enforced check is skipped on a path: a call on this past the proxy,"
            + " a request that ignoring() or an earlier rule lets through, a call to another service without the"
            + " caller's token", CALL_PATHS, CALL_CREDENTIALS),
    FINDING_UNRECOGNIZED_CHECK(Area.FINDINGS, "UNRECOGNIZED_CHECK: hand-rolled code that reads the caller and denies,"
            + " outside the mechanisms Spring enforces", CALL_PATHS),
    FINDING_AUTHORITIES_IN_CODE(Area.FINDINGS, "AUTHORITIES_IN_CODE: the checks after some code see an"
            + " Authentication other than the caller's: code sets it itself, or a check runs on a pooled thread that"
            + " keeps another request's", AUTHORITY_SOURCE, CALL_PATHS),
    FINDING_OPAQUE_CALLPATH(Area.FINDINGS, "OPAQUE_CALLPATH: a path goes through code the scan can't follow, shown"
            + " as an Opaque step", CALL_PATHS),
    FINDING_OPAQUE_CONFIG(Area.FINDINGS, "OPAQUE_CONFIG: configuration or code the scan can't read: a role hierarchy"
            + " built at runtime, a matcher it can't evaluate, a call's target or credentials", APPLICATION_GRAPH),
    FINDING_CHECK_AFTER_COMMIT(Area.FINDINGS, "CHECK_AFTER_COMMIT: a post-phase check decides after the method's"
            + " transaction has committed", METHOD_SECURITY),
    FINDING_ALWAYS_DENIED(Area.FINDINGS, "ALWAYS_DENIED: a check no caller can pass, e.g. hasPermission with no"
            + " PermissionEvaluator, a method check on a path that has no caller, or an authority no token carries",
            REQUIREMENTS, CALL_PATHS, AUTHORITY_SOURCE, CALL_CREDENTIALS),
    FINDING_ALWAYS_GRANTED(Area.FINDINGS, "ALWAYS_GRANTED: a check every caller passes although it reads as if it"
            + " asks for something, e.g. a role callers who haven't signed in hold", REQUIREMENTS),
    FINDING_OPEN_SENSITIVE_ENDPOINT(Area.FINDINGS, "OPEN_SENSITIVE_ENDPOINT: a library endpoint that hands out"
            + " secrets or control answers callers who haven't signed in", LIBRARY_ENDPOINTS, REQUEST_RULES),
    FINDING_PROVIDED_CONFLICT(Area.FINDINGS, "PROVIDED_CONFLICT: a local Provided fact lost to the organisation's",
            PROVIDED_FACTS),
    FINDING_RUNTIME_ONLY_CHECK(Area.FINDINGS, "RUNTIME_ONLY_CHECK: traces show a check the static graph doesn't have",
            TRACE_OBSERVATIONS),
    FINDING_UNMATCHED_CALL(Area.FINDINGS, "UNMATCHED_CALL: a traced call between services that matches no call or"
            + " entry point in the graphs", TRACE_OBSERVATIONS),
    FINDING_TOKEN_REJECTED(Area.FINDINGS, "TOKEN_REJECTED: the called service may reject the token a call brings,"
            + " for its audience or its scopes", CALL_CREDENTIALS, SYSTEM_GRAPH),

    // What the graphs answer.

    EXPOSURES(Area.ANALYSIS, "What a caller needs to reach each endpoint, and each field of its response, through"
            + " every service on the way, with where each requirement comes from", REQUIREMENTS, FIELD_LINEAGE,
            SYSTEM_GRAPH),
    POLICIES(Area.ANALYSIS, "Data governance and endpoint policies: fields with a label, and matching endpoints, must"
            + " require at least what the policy says", EXPOSURES, PROVIDED_FACTS),
    DIFF(Area.ANALYSIS, "Two revisions compared: each change to an exposure or a finding classified (weakened,"
            + " changed, strengthened, new, removed), failing when authorization got weaker; for a pull request, two"
            + " revisions of a project scanned", EXPOSURES, PROJECT_BUILDS),
    DIAGONAL_ESCALATION(Area.ANALYSIS, "A new route to data that asks less than every route that reached it before",
            DIFF, FIELD_LINEAGE),
    SARIF_ANNOTATIONS(Area.ANALYSIS, "A diff's changes as SARIF, placed on the source lines a pull request touches",
            DIFF),
    AGENT_REPORT(Area.ANALYSIS, "A diff explained for a coding agent's hook: what got weaker and what to do about it",
            DIFF),

    // How people get the answers.

    COMMAND_LINE(Area.DELIVERY, "The command line and its Gradle tasks: scan, link, diff, exposures, policies,"
            + " identities", APPLICATION_GRAPH, PROJECT_BUILDS),
    SCANNER_IMAGE(Area.DELIVERY, "The scanner image: the built jars and wars in one directory scanned into graphs in"
            + " another, refusing to run with a network, as root or past its time limit", BUILT_ARTIFACTS),
    GRAPH_SERVER(Area.DELIVERY, "The server: graphs published, stored and linked, and served with their exposures"
            + " over the REST API", SYSTEM_GRAPH, EXPOSURES),
    UI(Area.DELIVERY, "The web UI's shell: the services, the system model it draws from, navigation, details and"
            + " themes", GRAPH_SERVER),
    PATHS_VIEW(Area.DELIVERY, "The UI's request paths: alike paths merged into one card, steps laid out in lanes,"
            + " with what traces observed of them", UI, CALL_PATHS, TRACE_OBSERVATIONS),
    LINEAGE_VIEW(Area.DELIVERY, "The UI's field lineage: classes as boxes, flows as arrows, each field with its"
            + " checks", UI, FIELD_LINEAGE, FIELD_CHECKS),
    EXPOSURES_VIEW(Area.DELIVERY, "The UI's exposures table: what each endpoint and field asks of a caller, and the"
            + " policies it breaks", UI, EXPOSURES, POLICIES),
    FINDINGS_VIEW(Area.DELIVERY, "The UI's findings, alike ones folded into one, and the Provided facts applied",
            UI),
    IDENTITIES_VIEW(Area.DELIVERY, "The UI's identities and the grants they never used", UI, IDENTITIES),
    DIFF_VIEW(Area.DELIVERY, "The UI's diff report, opened from a diff's JSON", UI, DIFF),
    LEGEND_VIEW(Area.DELIVERY, "The UI's legend: what each kind of step, link and finding means", UI);

    /**
     * The part of AuthTracer's response a feature belongs to, in the order the guide presents them.
     */
    public enum Area {
        GRAPH("The graph"),
        ENTRY_POINTS("Entry points"),
        CHECKS("Checks"),
        FIELDS("Fields"),
        CALLS("Calls out"),
        SYSTEM("The system"),
        FINDINGS("Findings"),
        ANALYSIS("Analysis"),
        DELIVERY("Delivery");

        private final String title;

        Area(String title) {
            this.title = title;
        }

        public String title() {
            return title;
        }
    }

    private final Area area;
    private final String summary;
    private final List<Feature> requires;

    Feature(Area area, String summary, Feature... requires) {
        this.area = area;
        this.summary = summary;
        this.requires = List.of(requires);
    }

    public Area area() {
        return area;
    }

    /**
     * What the feature gives, in a sentence.
     */
    public String summary() {
        return summary;
    }

    /**
     * The features whose code this one relies on.
     */
    public List<Feature> requires() {
        return requires;
    }
}
