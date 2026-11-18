package dev.crain.authtracer.scan.spring;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.GraphBuilder;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootMethod;

/**
 * Entry points nobody calls: a message listener (decision 0044), a scheduled task (decision 0046), or a plain
 * WebSocket handler's messages (decision 0050). Spring Security
 * 7.1.1's method interceptors throw {@code AuthenticationCredentialsNotFoundException} when the
 * {@code SecurityContext} has no {@code Authentication}, which their threads don't, so a method check on such a path
 * fails unless the code sets a {@code SecurityContext} on the way; only {@code permitAll()} doesn't ask for the
 * caller. On that path the check is its own location that denies, {@code @PreAuthorize (no caller)}; the check
 * itself, which other paths share, keeps its requirement.
 */
@Supports({Feature.MESSAGE_LISTENERS, Feature.SCHEDULED_TASKS, Feature.WEBSOCKET_MESSAGES, Feature.CALL_PATHS})
final class NoCaller {

    private static final Set<String> SETS_CONTEXT = Set.of(
            "org.springframework.security.core.context.SecurityContextHolder#setContext",
            "org.springframework.security.core.context.SecurityContextHolderStrategy#setContext",
            "org.springframework.security.core.context.SecurityContext#setAuthentication",
            "org.springframework.security.core.context.SecurityContextImpl#setAuthentication");

    private static final String ASYNC = ":async";
    private static final String OTHER_THREAD = ":thread";
    /**
     * Decision 0084: the copy on another thread whose caller waits for it.
     */
    private static final String WAITED = "-waited";

    private NoCaller() {
    }

    /**
     * A WebFlux WebSocket session has its handshake's user in its Reactor Context, so it isn't one of these.
     */
    static boolean applies(Ingress ingress) {
        return MessageListeners.isListener(ingress) || ScheduledTasks.isScheduled(ingress)
                || WebSocketHandlers.isWebSocket(ingress) && !WebSocketHandlers.reactive(ingress);
    }

    /**
     * @param withCaller the nodes the request reaches with its caller before the entry point takes messages: a
     *        WebSocket handshake's rules, filters and interceptors
     */
    @Supports(Feature.FINDING_ALWAYS_DENIED)
    static void mark(GraphBuilder graph, Ingress entry, List<CallTraversal.Step> steps, Set<JavaSootMethod> walked,
            Set<String> withCaller) {
        if (walked.stream().anyMatch(NoCaller::setsSecurityContext)) {
            return;
        }
        String when = ScheduledTasks.isScheduled(entry) ? entry.endpoint() + " runs"
                : WebSocketHandlers.isWebSocket(entry) ? entry.endpoint() + " takes a message (the handshake's user is"
                        + " only the session's principal)"
                : entry.endpoint() + " delivers a message";
        Set<String> reported = new HashSet<>();
        for (int i = 0; i < steps.size(); i++) {
            CallTraversal.Step step = steps.get(i);
            if (!(graph.find(step.nodeId()).orElse(null) instanceof AuthorizationLocation location)
                    || !asksForCaller(location) || withCaller.contains(step.nodeId())) {
                continue;
            }
            AuthorizationLocation denied = denied(graph, location);
            steps.set(i, new CallTraversal.Step(denied.id(), step.via(), step.conditional()));
            if (reported.add(location.id())) {
                graph.finding(new Finding(Finding.Kind.ALWAYS_DENIED, location.mechanism() + " on "
                        + location.target().className() + "#" + location.target().method() + " runs when " + when
                        + ", which has no caller: it finds no Authentication in the SecurityContext and throws"
                        + " AuthenticationCredentialsNotFoundException, so it fails there unless the code sets a"
                        + " SecurityContext first", location.target()));
            }
        }
    }

    /**
     * Whether a check asks for the caller: a method or field check other than {@code permitAll()}.
     */
    static boolean asksForCaller(AuthorizationLocation location) {
        return location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST && !isOffThread(location.id())
                && !location.id().endsWith(WAITED) && !location.requirement().permitsAnyone();
    }

    /**
     * The check where nobody called: it denies.
     */
    static AuthorizationLocation denied(GraphBuilder graph, AuthorizationLocation location) {
        return copy(graph, location, ":no-caller", " (no caller)");
    }

    /**
     * The check on an {@code @Async} thread (decision 0048), or on another thread the code hands work to (decision
     * 0062): it denies the work there, not the caller, whose request has already gone on; so it is conditional on the
     * path.
     */
    static AuthorizationLocation offThread(GraphBuilder graph, AuthorizationLocation location, boolean async) {
        return async ? copy(graph, location, ASYNC, " (@Async)")
                : copy(graph, location, OTHER_THREAD, " (other thread)");
    }

    /**
     * Decision 0084: the check on another thread whose caller waits for its result ({@code get()}, {@code join()},
     * {@code block()}, or the handler returning it to Spring): its failure is the caller's, so it denies the request,
     * on the path like any check.
     */
    static AuthorizationLocation waitedOffThread(GraphBuilder graph, AuthorizationLocation location, boolean async) {
        return async ? copy(graph, location, ASYNC + WAITED, " (@Async, waited for)")
                : copy(graph, location, OTHER_THREAD + WAITED, " (other thread, waited for)");
    }

    static boolean isOffThread(String locationId) {
        return locationId.endsWith(ASYNC) || locationId.endsWith(OTHER_THREAD);
    }

    private static AuthorizationLocation copy(GraphBuilder graph, AuthorizationLocation location, String suffix,
            String note) {
        return graph.node(new AuthorizationLocation(location.id() + suffix, location.mechanism() + note,
                location.scope(), location.phase(), Requirement.denyAll(), location.target(), location.field(),
                location.routePattern(), location.denial(), location.proxied(), location.fieldOwner()));
    }

    private static boolean setsSecurityContext(JavaSootMethod method) {
        return method.hasBody() && method.getBody().getStmts().stream().filter(Stmt::isInvokableStmt)
                .flatMap(stmt -> stmt.asInvokableStmt().getInvokeExpr().stream())
                .map(invoke -> invoke.getMethodSignature())
                .anyMatch(signature -> SETS_CONTEXT.contains(signature.getDeclClassType().getFullyQualifiedName()
                        + "#" + signature.getName()));
    }
}
