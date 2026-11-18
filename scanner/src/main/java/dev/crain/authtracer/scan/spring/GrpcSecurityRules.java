package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.AuthorizationLocation.Scope;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Rule;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0032: Spring gRPC's request rules, from the interceptor bean methods that build an
 * {@code AuthenticationProcessInterceptor} with {@code GrpcSecurity#authorizeRequests}: {@code methods("pkg.Service/*")} and {@code allRequests()} patterns on the
 * full method name, first match wins, and a call no rule matches is denied (1.1.1
 * {@code RequestMapperAuthorizationManager}). The interceptor runs only for the services it is applied to: all of them
 * as a {@code @GlobalServerInterceptor}, else those whose {@code @GrpcService} lists it by type or bean name. HTTP
 * chains don't see gRPC calls on Spring gRPC's own server, and these rules don't see HTTP requests.
 */
@Supports(Feature.REQUEST_RULES)
final class GrpcSecurityRules {

    private static final String INTERCEPTOR = "org.springframework.grpc.server.security.AuthenticationProcessInterceptor";
    private static final String GLOBAL = "org.springframework.grpc.server.GlobalServerInterceptor";
    private static final String GRPC_SERVICE = "org.springframework.grpc.server.service.GrpcService";
    static final String MECHANISM = "authorizeRequests (gRPC)";

    private record Chain(JavaSootMethod beanMethod, int order, List<Rule> rules, boolean authorizes, boolean global) {
    }

    private final ScanContext context;
    private final GraphBuilder graph;
    private final Set<String> reported = new HashSet<>();
    private final List<Chain> chains = new ArrayList<>();

    @Supports(Feature.FINDING_NOT_ENFORCED)
    GrpcSecurityRules(ScanContext context, GraphBuilder graph, SpelRequirements spel) {
        this.context = context;
        this.graph = graph;
        SecurityDsl dsl = new SecurityDsl(context, spel, false, null, "", Set.of());
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                // Typed as the AuthenticationProcessInterceptor it builds, or as any ServerInterceptor.
                if (method.hasBody() && context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getParameterTypes().stream().anyMatch(type -> type instanceof ClassType parameter
                                && parameter.getFullyQualifiedName().equals(SecurityDsl.GRPC_SECURITY))) {
                    SecurityDsl.Interpretation found = dsl.grpcChain(method);
                    chains.add(new Chain(method, HttpSecurityRules.order(context, method), found.rules,
                            found.authorizes, context.hasAnnotation(method, GLOBAL)));
                }
            }
        }
        chains.sort(Comparator.comparingInt(Chain::order));
        for (Chain chain : chains) {
            if (!chain.global() && context.applicationClasses().stream().noneMatch(cls -> applies(chain, cls))) {
                graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "The AuthenticationProcessInterceptor bean "
                        + MethodNames.key(chain.beanMethod().getSignature()) + " is not a @GlobalServerInterceptor"
                        + " and no @GrpcService lists it, so Spring gRPC never runs its rules",
                        MethodNames.codeRef(chain.beanMethod().getSignature())));
            }
        }
    }

    /**
     * The request-level checks on a gRPC call to a service: one per interceptor that applies to it (each must pass).
     */
    List<AuthorizationLocation> locationsFor(Ingress ingress, JavaSootClass service) {
        List<AuthorizationLocation> locations = new ArrayList<>();
        for (Chain chain : chains) {
            if (!chain.authorizes() || !chain.global() && !applies(chain, service)) {
                continue;
            }
            locations.add(location(chain, ingress));
        }
        return locations;
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private AuthorizationLocation location(Chain chain, Ingress ingress) {
        String key = MethodNames.key(chain.beanMethod().getSignature());
        List<AuthorizationLocation> mayMatch = new ArrayList<>();
        for (int i = 0; i < chain.rules().size(); i++) {
            Rule rule = chain.rules().get(i);
            if (rule.matcher().matches(ingress.httpMethod(), ingress.route())) {
                return maybeFirst(mayMatch, rule(chain, key, i, rule));
            }
            if (rule.matcher().mayMatch()) {
                AuthorizationLocation maybe = rule(chain, key, i, rule);
                mayMatch.add(maybe);
                if (reported.add(maybe.id())) {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The gRPC rule " + rule.matcher().describe()
                            + " in " + key + " matches methods AuthTracer can't read: the calls it matches get its"
                            + " requirement instead of the rules after it", maybe.target()));
                }
            }
        }
        return maybeFirst(mayMatch, graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + key
                + ":unmatched", MECHANISM + " (no rule matched: denied by default)", Scope.HTTP_REQUEST, Phase.PRE,
                Requirement.denyAll(), MethodNames.codeRef(chain.beanMethod().getSignature()), null, "unmatched",
                Denial.THROW, false)));
    }

    private AuthorizationLocation rule(Chain chain, String key, int index, Rule rule) {
        String pattern = rule.matcher().describe();
        return graph.node(new AuthorizationLocation("location:HTTP_REQUEST:" + key + ":" + index + ":" + pattern,
                MECHANISM, Scope.HTTP_REQUEST, Phase.PRE, rule.requirement(),
                MethodNames.codeRef(chain.beanMethod().getSignature()).atLine(rule.line()), null, pattern,
                Denial.THROW, false));
    }

    /**
     * Rules before the matching one that may match the call first (decision 0051): a Split asking for the weakest
     * of them and the matching rule (decision 0027).
     */
    private AuthorizationLocation maybeFirst(List<AuthorizationLocation> mayMatch, AuthorizationLocation matched) {
        if (mayMatch.isEmpty()) {
            return matched;
        }
        List<AuthorizationLocation> alternatives = new ArrayList<>(mayMatch);
        alternatives.add(matched);
        List<Requirement> requirements = alternatives.stream().map(AuthorizationLocation::requirement).distinct()
                .toList();
        return graph.split(new AuthorizationLocation("location:SPLIT:" + matched.id() + ":or:" + mayMatch.stream()
                .map(AuthorizationLocation::id).toList(), MECHANISM + " (a rule may match first)", Scope.HTTP_REQUEST,
                Phase.PRE, requirements.size() == 1 ? requirements.getFirst() : Requirement.or(requirements),
                matched.target(), null, String.join(" or ", alternatives.stream()
                        .map(AuthorizationLocation::routePattern).toList()), Denial.THROW, false),
                GraphBuilder.Split.of(alternatives.stream().map(AuthorizationLocation::id).toList()));
    }

    /**
     * @param service the application's service class; {@code null} for a library's service, which only global
     *        interceptors check
     */
    private boolean applies(Chain chain, JavaSootClass service) {
        if (service == null) {
            return false;
        }
        Optional<AnnotationUsage> annotation = context.findAnnotation(service, GRPC_SERVICE);
        return annotation.isPresent() && (Annotations.strings(annotation.get(), "interceptors").contains(INTERCEPTOR)
                || Annotations.strings(annotation.get(), "interceptorNames").contains(chain.beanMethod().getName()));
    }
}
