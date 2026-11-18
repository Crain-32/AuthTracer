package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.AuthorizationLocation.Scope;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.graph.ControlFlowGraph;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.JReturnVoidStmt;
import sootup.core.jimple.common.stmt.JThrowStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.FieldSignature;
import sootup.core.types.Type;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0066 (AUTHZ-11): a check the code makes itself with a manager. {@code manager.verify(authentication,
 * object)} throws {@code AuthorizationDeniedException} when the result isn't granted (7.1.1
 * {@code AuthorizationManager#verify}), and {@code manager.authorize(..)} counts when its result decides a throw or a
 * return; either is a method check at the call site, before what follows. Its requirement is the manager's: one of
 * Spring's built-in managers (decision 0063), or the custom code that decides it (decisions 0064, 0065).
 */
@Supports(Feature.CUSTOM_DECISIONS)
final class ProgrammaticChecks {

    static final String MECHANISM = "AuthorizationManager";
    private static final Set<String> MANAGERS = Set.of(DecisionCode.AUTHORIZATION_MANAGER,
            DecisionCode.REACTIVE_MANAGER);
    private static final String AUTHORIZATION_DECISION = BuiltInManagers.PACKAGE + "AuthorizationDecision";

    /**
     * A manager as AuthTracer read it.
     *
     * @param hierarchy whether the RoleHierarchy widens it: custom code, as everywhere (decision 0065), or a built-in
     *        manager given it with {@code setRoleHierarchy(..)}; Spring's factories give theirs none
     */
    private record Read(Requirement requirement, boolean hierarchy) {
    }

    private final ScanContext context;
    private final GraphBuilder graph;
    private final DecisionCode decisionCode;
    private final Set<String> withoutHierarchy = new HashSet<>();
    private final Set<String> checking = new LinkedHashSet<>();
    private final StructureRules rules;

    ProgrammaticChecks(ScanContext context, GraphBuilder graph) {
        this.context = context;
        this.graph = graph;
        this.decisionCode = DecisionCode.of(context);
        this.rules = new StructureRules(context, graph, new SpelRequirements("ROLE_").withBeans(decisionCode));
    }

    /**
     * The check a call on the path makes, if it is one.
     *
     * @param site where the call is, named by the method it is written in
     */
    @Supports({Feature.FINDING_UNRECOGNIZED_CHECK, Feature.FINDING_OPAQUE_CONFIG})
    Optional<AuthorizationLocation> detect(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke,
            CodeRef site) {
        // Decision 0120: a call to an authorization library's method, as a rule describes it. Inside that method,
        // the rule stands for what it calls.
        if (rules.describes(caller)) {
            return Optional.empty();
        }
        Optional<AuthorizationLocation> ruled = rules.call(caller, invoke, site);
        if (ruled.isPresent()) {
            checking.add(MethodNames.key(caller.getSignature()));
            return ruled;
        }
        String name = invoke.getMethodSignature().getName();
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance) || !name.equals("verify")
                && !name.equals("authorize") || !SpringBeans.assignable(context, invoke.getMethodSignature()
                        .getDeclClassType(), MANAGERS) || !(instance.getBase() instanceof Local receiver)
                || decides(caller)) {
            return Optional.empty();
        }
        boolean reactive = SpringBeans.assignable(context, invoke.getMethodSignature().getDeclClassType(),
                Set.of(DecisionCode.REACTIVE_MANAGER));
        String where = MethodNames.key(caller.getSignature());
        if (name.equals("authorize") && !gates(caller, stmt)) {
            graph.finding(new Finding(Finding.Kind.UNRECOGNIZED_CHECK, where + " asks an AuthorizationManager"
                    + " (authorize(..)) but AuthTracer can't see the answer deny anything, so the path shows no check:"
                    + " verify(..) throws when it isn't granted", site));
            return Optional.empty();
        }
        if (name.equals("verify") && reactive && !(stmt instanceof AbstractDefinitionStmt)) {
            graph.finding(new Finding(Finding.Kind.UNRECOGNIZED_CHECK, where + " calls verify(..) on a"
                    + " ReactiveAuthorizationManager but drops the Mono it returns, so nothing subscribes to it and it"
                    + " checks nothing", site));
            return Optional.empty();
        }
        String expression = name + "(" + MethodNames.simpleName(receiver.getType().toString()) + ")";
        Read read = manager(caller, receiver, expression, 0).orElseGet(() -> {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, where + " checks with an AuthorizationManager"
                    + " AuthTracer can't read: the check is shown as opaque", site));
            return new Read(Requirement.expression(expression), true);
        });
        AuthorizationLocation location = graph.node(new AuthorizationLocation("location:METHOD:" + site.key() + ":"
                + MECHANISM + "#" + name + "@" + site.line(), MECHANISM + "#" + name, Scope.METHOD, Phase.PRE,
                read.requirement(), site, null, null, Denial.THROW, false));
        if (!read.hierarchy()) {
            withoutHierarchy.add(location.id());
        }
        checking.add(where);
        return Optional.of(location);
    }

    /**
     * Whether the RoleHierarchy widens the check.
     */
    boolean hierarchyAware(AuthorizationLocation location) {
        return !withoutHierarchy.contains(location.id());
    }

    /**
     * Whether a method on a path checks with a manager, or is the check a call rule describes: what it reads of the
     * caller to do so isn't a hand-rolled check.
     */
    boolean checks(JavaSootMethod method) {
        return checking.contains(MethodNames.key(method.getSignature())) || rules.describes(method);
    }

    /**
     * A manager's own decision method, which decision code reads (decision 0065), not a check on the path.
     */
    private boolean decides(JavaSootMethod caller) {
        return Set.of("authorize", "verify").contains(caller.getName())
                && SpringBeans.assignable(context, caller.getDeclaringClassType(), MANAGERS);
    }

    /**
     * Whether the call's result decides a branch whose ways leave the method differently: one throws or returns
     * where the other goes on, as in {@code if (!result.isGranted()) throw ..}.
     */
    private static boolean gates(JavaSootMethod caller, Stmt call) {
        if (!(call instanceof AbstractDefinitionStmt definition) || !(definition.getLeftOp() instanceof Local result)) {
            return false;
        }
        ControlFlowGraph<?> stmts = caller.getBody().getControlFlowGraph();
        Set<Value> derived = new HashSet<>(List.of(result));
        for (Stmt stmt : caller.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt assign && assign.getLeftOp() instanceof Local local
                    && assign.getRightOp().getUses().stream().anyMatch(derived::contains)) {
                derived.add(local);
            }
            if (stmt instanceof JIfStmt branch && branch.getCondition().getUses().stream()
                    .anyMatch(derived::contains)) {
                List<Stmt> ways = stmts.successors(branch);
                if (ways.size() == 2 && !exits(stmts, ways.get(0)).equals(exits(stmts, ways.get(1)))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The throws and returns reachable from the statement.
     */
    private static Set<Stmt> exits(ControlFlowGraph<?> stmts, Stmt start) {
        Set<Stmt> seen = new HashSet<>(List.of(start));
        Set<Stmt> exits = new HashSet<>();
        Deque<Stmt> queue = new ArrayDeque<>(List.of(start));
        while (!queue.isEmpty()) {
            Stmt stmt = queue.removeFirst();
            if (stmt instanceof JThrowStmt || stmt instanceof JReturnStmt || stmt instanceof JReturnVoidStmt) {
                exits.add(stmt);
            }
            stmts.successors(stmt).stream().filter(seen::add).forEach(queue::add);
        }
        return exits;
    }

    /**
     * What the manager in the local is: one of Spring's factories' (or composed of them), a {@code new} of the
     * application's, a parameter, or a field set from one of those.
     */
    private Optional<Read> manager(JavaSootMethod method, Local local, String expression, int depth) {
        Optional<Value> definition = Locals.definition(method.getBody(), local);
        if (definition.isEmpty() || depth > 4) {
            return Optional.empty();
        }
        Optional<Read> read = switch (definition.get()) {
            case JNewExpr created -> decisionCode.created(created.getType(), expression)
                    .map(requirement -> new Read(requirement, true));
            case JParameterRef parameter -> injected(method.getParameterType(parameter.getIndex()),
                    method.getBody().getParameterLocal(parameter.getIndex()).getName(), expression);
            case AbstractInvokeExpr call when !(call instanceof AbstractInstanceInvokeExpr) -> BuiltInManagers
                    .factory(call.getMethodSignature().getDeclClassType().getFullyQualifiedName(),
                            call.getMethodSignature().getName(), call.getMethodSignature().getParameterTypes().stream()
                                    .map(Object::toString).toList(), arguments(method, call, depth))
                    .map(requirement -> new Read(requirement, false));
            case JFieldRef field -> field(field.getFieldSignature(), expression, depth);
            default -> Optional.empty();
        };
        return read.map(found -> !found.hierarchy() && givenHierarchy(method, local)
                ? new Read(found.requirement(), true) : found);
    }

    private Optional<Read> injected(Type type, String name, String expression) {
        return decisionCode.injected(type, name, expression).map(requirement -> new Read(requirement, true));
    }

    /**
     * Decision 0063: {@code manager.setRoleHierarchy(..)} gives a built-in manager the RoleHierarchy.
     */
    private static boolean givenHierarchy(JavaSootMethod method, Local manager) {
        return method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .anyMatch(invoke -> invoke.getMethodSignature().getName().equals("setRoleHierarchy")
                        && invoke instanceof AbstractInstanceInvokeExpr instance && instance.getBase().equals(manager));
    }

    /**
     * A field's manager: what a constructor or initializer of its class stores into it, else the bean of its type.
     */
    private Optional<Read> field(FieldSignature field, String expression, int depth) {
        Optional<JavaSootClass> owner = context.findClass(field.getDeclClassType());
        for (JavaSootMethod method : owner.map(JavaSootClass::getMethods).orElse(Set.of())) {
            if (!method.hasBody() || !method.getName().equals("<init>") && !method.getName().equals("<clinit>")) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt store && store.getLeftOp() instanceof JFieldRef target
                        && target.getFieldSignature().equals(field) && store.getRightOp() instanceof Local value) {
                    Optional<Read> stored = manager(method, value, expression, depth + 1);
                    if (stored.isPresent()) {
                        return stored;
                    }
                }
            }
        }
        return injected(field.getType(), field.getName(), expression);
    }

    /**
     * A factory call's arguments as the built-in managers' table reads them: strings, string arrays, managers and
     * arrays of them, and a default {@code AuthorizationDecision}.
     */
    private List<BuiltInManagers.Arg> arguments(JavaSootMethod method, AbstractInvokeExpr call, int depth) {
        List<BuiltInManagers.Arg> args = new ArrayList<>();
        for (Value arg : call.getArgs()) {
            args.add(argument(method, arg, depth));
        }
        return args;
    }

    private BuiltInManagers.Arg argument(JavaSootMethod method, Value arg, int depth) {
        if (arg instanceof StringConstant constant) {
            return new BuiltInManagers.Text(constant.getValue());
        }
        if (!(arg instanceof Local local)) {
            return BuiltInManagers.UNKNOWN;
        }
        Optional<Value> definition = Locals.definition(method.getBody(), local);
        if (definition.orElse(null) instanceof JNewArrayExpr array) {
            List<Value> elements = Locals.elements(method.getBody(), local);
            if (array.getBaseType().toString().equals("java.lang.String")) {
                List<String> strings = Locals.strings(method.getBody(), local);
                return new BuiltInManagers.Texts(strings, strings.size() == elements.size());
            }
            List<Requirement> managers = new ArrayList<>();
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt store && store.getLeftOp() instanceof JArrayRef element
                        && element.getBase().equals(local) && store.getRightOp() instanceof Local value) {
                    manager(method, value, MECHANISM, depth + 1).ifPresent(read -> managers.add(read.requirement()));
                }
            }
            return new BuiltInManagers.Managers(managers, managers.size() == elements.size());
        }
        if (definition.orElse(null) instanceof JNewExpr created && created.getType().getFullyQualifiedName()
                .equals(AUTHORIZATION_DECISION)) {
            return decision(method, local);
        }
        return manager(method, local, MECHANISM, depth + 1)
                .map(read -> (BuiltInManagers.Arg) new BuiltInManagers.Manager(read.requirement()))
                .orElse(BuiltInManagers.UNKNOWN);
    }

    /**
     * {@code new AuthorizationDecision(granted)}.
     */
    private static BuiltInManagers.Arg decision(JavaSootMethod method, Local local) {
        return method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke.getMethodSignature().getName().equals("<init>")
                        && invoke instanceof AbstractInstanceInvokeExpr instance && instance.getBase().equals(local)
                        && invoke.getArgCount() == 1 && invoke.getArg(0) instanceof IntConstant)
                .findFirst().map(invoke -> (BuiltInManagers.Arg) new BuiltInManagers.Decision(
                        ((IntConstant) invoke.getArg(0)).getValue() != 0))
                .orElse(BuiltInManagers.UNKNOWN);
    }
}
