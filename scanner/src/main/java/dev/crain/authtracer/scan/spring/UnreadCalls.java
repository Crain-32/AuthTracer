package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0082: a call AuthTracer recognises but whose target it can't read (a URL from a parameter, a topic built at
 * run time) is still an Egress, with what is known (its client, method and base URL) and the target
 * {@link Egress#UNKNOWN_TARGET}, which the linker places nowhere, and an {@code OPAQUE_CONFIG} finding that says what
 * couldn't be read. Dropping it would make the graph look as if the service called nothing there.
 */
@Supports({Feature.FINDING_OPAQUE_CONFIG, Feature.SERVICE_CALLS, Feature.MESSAGE_SENDS})
final class UnreadCalls {

    private final Set<Finding> findings = new LinkedHashSet<>();

    /**
     * @param what what the call names that isn't known: {@code path}, {@code topic}, {@code route}, ...
     * @param why where it comes from, e.g. {@code a parameter} ({@link #origin})
     * @param baseUrl the service it goes to, {@code null} when that isn't known either
     */
    Egress egress(String client, String method, String what, String baseUrl, String baseUrlExpression,
            JavaSootMethod caller, Stmt stmt, String why, Payload response) {
        CodeRef site = MethodNames.codeRef(caller.getSignature(), stmt);
        // One per client and service in a method: what each reaches there is unknown alike, but a topic is not a
        // binding, and one service not another.
        Egress egress = new Egress("egress:" + site.key() + " " + method + " " + Egress.UNKNOWN_TARGET + " " + client
                + (baseUrl == null ? "" : " " + baseUrl), client, method, Egress.UNKNOWN_TARGET, baseUrl,
                baseUrlExpression, site, response, null, null);
        String to = baseUrl != null ? " to " + baseUrl : baseUrlExpression != null ? " to " + baseUrlExpression : "";
        findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The " + client + " call in "
                + MethodNames.key(caller.getSignature()) + " sends " + method + to + " with a " + what
                + " AuthTracer can't read (" + why + "): its Egress is " + method + " "
                + Egress.UNKNOWN_TARGET + ", which links to nothing", egress.callSite()));
        return egress;
    }

    List<Finding> findings() {
        return new ArrayList<>(findings);
    }

    /**
     * Where a value comes from, as far as one look back tells: a parameter, a field, a call's result.
     */
    static String origin(JavaSootMethod method, Value value) {
        if (!(value instanceof Local local)) {
            return "a value AuthTracer can't follow";
        }
        if (Locals.parameterIndex(method.getBody(), local).isPresent()) {
            return "a parameter";
        }
        Value definition = Locals.definition(method.getBody(), local).orElse(null);
        if (definition instanceof JCastExpr cast) {
            return origin(method, cast.getOp());
        }
        if (definition instanceof JFieldRef field) {
            return "the field " + field.getFieldSignature().getName();
        }
        if (definition instanceof JDynamicInvokeExpr dynamic) {
            return dynamic.getBootstrapMethodSignature().getName().equals("makeConcatWithConstants")
                    ? "a concatenation" : GroovyCalls.of(dynamic).map(call -> "what the dynamic Groovy call "
                            + call.name() + "(..) returns").orElse("a function");
        }
        if (definition instanceof AbstractInvokeExpr call) {
            return "what " + MethodNames.simpleName(call.getMethodSignature().getDeclClassType()
                    .getFullyQualifiedName()).replace('$', '.') + "." + call.getMethodSignature().getName()
                    + "(..) returns";
        }
        if (definition instanceof JNewExpr created) {
            return "a new " + MethodNames.simpleName(created.getType().getFullyQualifiedName()).replace('$', '.');
        }
        return "a value AuthTracer can't follow";
    }
}
