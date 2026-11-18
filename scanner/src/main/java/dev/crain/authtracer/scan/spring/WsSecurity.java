package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0056: WS-Security authenticates SOAP messages outside the HTTP filter chain. Spring WS 5.0.2's
 * {@code Wss4jSecurityInterceptor} (an endpoint interceptor, {@code WsConfigurer#addInterceptors}) validates a
 * message's {@code UsernameToken}, then hands its principal to its validation callback handlers. Spring WS's
 * {@code SpringSecurityPasswordValidationCallbackHandler} loads the user through its {@code UserDetailsService} for
 * each message ({@code handleUsernameToken}; a {@code NullUserCache} unless given another), and sets
 * {@code SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, password,
 * user.getAuthorities()))} ({@code handleUsernameTokenPrincipal}), cleared after the message: the endpoint's method
 * checks see that user, not the HTTP request's. Other handlers ({@code SimplePasswordValidationCallbackHandler})
 * validate the password without setting a {@code SecurityContext}.
 */
@Supports(Feature.AUTHORITY_SOURCE)
final class WsSecurity {

    private static final String HANDLER =
            "org.springframework.ws.soap.security.wss4j2.callback.SpringSecurityPasswordValidationCallbackHandler";
    private static final String NULL_CACHE = "org.springframework.security.core.userdetails.cache.NullUserCache";

    /**
     * A way in: as fresh as the user it loads, and how the authority source names it.
     */
    record Mechanism(Freshness freshness, String label) {
    }

    private WsSecurity() {
    }

    static List<Mechanism> detect(ScanContext context) {
        boolean handler = false;
        boolean cached = false;
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    if (stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JNewExpr created
                            && SpringBeans.assignable(context, created.getType(), Set.of(HANDLER))) {
                        handler = true;
                    }
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("setUserCache")
                            && SpringBeans.assignable(context, invoke.get().getMethodSignature().getDeclClassType(),
                                    Set.of(HANDLER))) {
                        cached |= !nullCache(method, invoke.get().getArg(0));
                    }
                }
            }
        }
        List<Mechanism> mechanisms = new ArrayList<>();
        if (handler) {
            // A user cache keeps what it loaded until the entry goes: a snapshot, the weaker claim.
            mechanisms.add(cached ? new Mechanism(Freshness.SNAPSHOT, "WS-Security UsernameToken (SOAP, user cache)")
                    : new Mechanism(Freshness.LIVE, "WS-Security UsernameToken (SOAP)"));
        }
        return mechanisms;
    }

    private static boolean nullCache(JavaSootMethod method, Value cache) {
        Optional<ClassType> created = cache instanceof Local local ? Locals.created(method.getBody(), local)
                : Optional.empty();
        return created.filter(type -> type.getFullyQualifiedName().equals(NULL_CACHE)).isPresent();
    }
}
