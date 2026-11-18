package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.JavaSootMethod;

/**
 * The {@code RoleHierarchy} bean (ROLE-01, ROLE-02). In Spring Security 7.1 one bean applies to
 * {@code authorizeHttpRequests} rules and to pre/post, {@code @Secured} and JSR-250 method security (each
 * configuration autowires it), so a {@code hasRole("USER")} check also admits every role that implies
 * {@code ROLE_USER}. Also reads the role prefix from a {@code GrantedAuthorityDefaults} bean.
 *
 * @param implies each role's directly implied roles, as declared
 */
@Supports(Feature.REQUIREMENTS)
record RoleHierarchies(SortedMap<String, SortedSet<String>> implies) {

    static final RoleHierarchies NONE = new RoleHierarchies(new TreeMap<>());

    private static final String ROLE_HIERARCHY = "org.springframework.security.access.hierarchicalroles.RoleHierarchy";
    private static final String ROLE_HIERARCHY_IMPL =
            "org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl";
    private static final String BUILDER = ROLE_HIERARCHY_IMPL + "$Builder";
    private static final String GRANTED_AUTHORITY_DEFAULTS = "org.springframework.security.config.core.GrantedAuthorityDefaults";
    private static final String IMPLIED_ROLES = BUILDER + "$ImpliedRoles";

    /**
     * Reads the first {@code RoleHierarchy} bean method; reports one it can't read.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    static RoleHierarchies detect(ScanContext context, GraphBuilder graph) {
        for (JavaSootMethod method : SpringBeans.beanMethods(context, ROLE_HIERARCHY, ROLE_HIERARCHY_IMPL)) {
            if (method.hasBody()) {
                Optional<RoleHierarchies> read = read(method);
                if (read.isEmpty()) {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RoleHierarchy bean "
                            + MethodNames.key(method.getSignature()) + " is not built from constants, so role"
                            + " checks may admit more roles than the graph shows",
                            MethodNames.codeRef(method.getSignature())));
                }
                return read.orElse(NONE);
            }
        }
        return NONE;
    }

    /**
     * ROLE-05: the prefix a {@code GrantedAuthorityDefaults} bean sets, {@code ROLE_} without one.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    static String rolePrefix(ScanContext context, GraphBuilder graph) {
        for (JavaSootMethod method : SpringBeans.beanMethods(context, GRANTED_AUTHORITY_DEFAULTS)) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("<init>")
                        && invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                .equals(GRANTED_AUTHORITY_DEFAULTS)
                        && invoke.get().getArgCount() == 1
                        && invoke.get().getArg(0) instanceof StringConstant prefix) {
                    return prefix.getValue();
                }
            }
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The GrantedAuthorityDefaults bean "
                    + MethodNames.key(method.getSignature()) + " does not set its role prefix from a constant;"
                    + " role checks are shown with ROLE_", MethodNames.codeRef(method.getSignature())));
        }
        return "ROLE_";
    }

    boolean isEmpty() {
        return implies.isEmpty();
    }

    /**
     * {@code ROLE_ADMIN > ROLE_STAFF} lines, as {@code RoleHierarchyImpl.fromHierarchy} takes them.
     */
    static RoleHierarchies parse(String hierarchy) {
        Map<String, SortedSet<String>> implies = new HashMap<>();
        for (String line : hierarchy.split("\n")) {
            String[] roles = line.trim().split("\\s+>\\s+");
            for (int i = 1; i < roles.length; i++) {
                implies.computeIfAbsent(roles[i - 1], role -> new TreeSet<>()).add(roles[i]);
            }
        }
        return new RoleHierarchies(new TreeMap<>(implies));
    }

    /**
     * Widens authority checks to every role that reaches one of the required authorities.
     */
    Requirement expand(Requirement requirement) {
        if (isEmpty()) {
            return requirement;
        }
        return switch (requirement.kind()) {
            case ANY_AUTHORITY -> requirement.withAuthorities(holders(requirement.authorities()));
            case ALL_AUTHORITIES -> {
                List<Requirement> each = requirement.authorities().stream()
                        .map(authority -> Requirement.anyAuthority(List.copyOf(holders(new TreeSet<>(List.of(
                                authority)))))).toList();
                boolean widened = each.stream().anyMatch(any -> any.authorities().size() > 1);
                yield widened ? new Requirement(Requirement.Kind.AND, null, each, requirement.expression(),
                        requirement.decidedBy()) : requirement;
            }
            case AND, OR, NOT -> requirement.withOperands(requirement.operands().stream().map(this::expand).toList());
            default -> requirement;
        };
    }

    /**
     * The required authorities plus every role whose reachable set includes one of them.
     */
    private SortedSet<String> holders(SortedSet<String> required) {
        SortedSet<String> holders = new TreeSet<>(required);
        for (String role : implies.keySet()) {
            if (reachable(role).stream().anyMatch(required::contains)) {
                holders.add(role);
            }
        }
        return holders;
    }

    private SortedSet<String> reachable(String role) {
        SortedSet<String> reached = new TreeSet<>();
        Deque<String> pending = new ArrayDeque<>(implies.getOrDefault(role, new TreeSet<>()));
        while (!pending.isEmpty()) {
            String next = pending.pop();
            if (reached.add(next)) {
                pending.addAll(implies.getOrDefault(next, new TreeSet<>()));
            }
        }
        return reached;
    }

    /**
     * A builder in progress: {@code withRolePrefix(..).role(..).implies(..)...build()}.
     */
    private static final class Builder {
        final String prefix;
        final StringBuilder lines = new StringBuilder();

        Builder(String prefix) {
            this.prefix = prefix;
        }
    }

    private record ImpliedRoles(Builder builder, String role) {
    }

    @Might("Follow the hierarchy string through @Value properties and helper methods")
    private static Optional<RoleHierarchies> read(JavaSootMethod method) {
        Map<Local, Object> values = evaluate(method);
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt ret) {
                return ret.getOp() instanceof Local local && values.get(local) instanceof RoleHierarchies hierarchy
                        ? Optional.of(hierarchy) : Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
     * A hierarchy built inside another bean method, e.g. passed to {@code setRoleHierarchy}.
     */
    static Optional<RoleHierarchies> inline(JavaSootMethod method, Local local) {
        return evaluate(method).get(local) instanceof RoleHierarchies hierarchy ? Optional.of(hierarchy)
                : Optional.empty();
    }

    @SuppressWarnings("unchecked")
    private static Map<Local, Object> evaluate(JavaSootMethod method) {
        Map<Local, Object> values = new HashMap<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (!(stmt instanceof AbstractDefinitionStmt definition)) {
                continue;
            }
            Value right = definition.getRightOp();
            if (definition.getLeftOp() instanceof JArrayRef array && values.get(array.getBase()) instanceof List<?> list) {
                Locals.text(right, values).ifPresent(((List<Object>) list)::add);
                continue;
            }
            if (!(definition.getLeftOp() instanceof Local local)) {
                continue;
            }
            Object value = null;
            if (right instanceof StringConstant constant) {
                value = constant.getValue();
            }
            else if (right instanceof Local other) {
                value = values.get(other);
            }
            else if (right instanceof JNewArrayExpr) {
                value = new ArrayList<>();
            }
            else if (right instanceof AbstractInvokeExpr invoke) {
                value = call(invoke, values);
            }
            if (value != null) {
                values.put(local, value);
            }
        }
        return values;
    }

    private static Object call(AbstractInvokeExpr invoke, Map<Local, Object> values) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        Object receiver = invoke instanceof AbstractInstanceInvokeExpr instance ? values.get(instance.getBase()) : null;
        List<Object> args = invoke.getArgs().stream().map(arg -> Locals.evaluated(arg, values)).toList();
        if (owner.equals(ROLE_HIERARCHY_IMPL)) {
            return switch (name) {
                case "fromHierarchy" -> args.getFirst() instanceof String text ? parse(text) : null;
                case "withDefaultRolePrefix" -> new Builder("ROLE_");
                case "withRolePrefix" -> args.getFirst() instanceof String prefix ? new Builder(prefix) : null;
                default -> null;
            };
        }
        if (owner.equals(BUILDER) && receiver instanceof Builder builder) {
            return switch (name) {
                case "role" -> args.getFirst() instanceof String role ? new ImpliedRoles(builder,
                        builder.prefix + role) : null;
                case "build" -> parse(builder.lines.toString());
                default -> null;
            };
        }
        if (owner.equals(IMPLIED_ROLES) && name.equals("implies") && receiver instanceof ImpliedRoles implied
                && args.getFirst() instanceof List<?> roles) {
            for (Object role : roles) {
                implied.builder().lines.append(implied.role()).append(" > ").append(implied.builder().prefix)
                        .append(role).append('\n');
            }
            return implied.builder();
        }
        return null;
    }

}
