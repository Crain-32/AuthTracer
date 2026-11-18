package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.graph.ControlFlowGraph;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.NullConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractConditionExpr;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JEqExpr;
import sootup.core.jimple.common.expr.JNeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JGotoStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.JThrowStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0065 (EXPR-03, AUTHZ-01, AUTHZ-02, EXPR-06, DENY-05, SRC-14): what a decision method decides, read from its
 * body one path at a time, within the method. Each path that returns a grant adds the conditions it took (a root
 * function such as {@code operations.hasRole("X")}, a built-in manager's {@code authorize(..)}, the Authentication's
 * authorities containing one), so the method decides the {@code or} of its granting paths. A path that throws denies,
 * as {@code AuthorizationDeniedException} does (DENY-05). A {@code null} decision abstains, which 7.1.1's
 * interceptors and {@code AuthorizationFilter} let through. A condition it can't read (a repository's answer, a call
 * on another object, a loop, a try block) leaves the method undecided; what it reads from a store or another service
 * is recorded either way.
 */
@Supports(Feature.CUSTOM_DECISIONS)
final class DecisionBodies {

    private static final int MAX_PATHS = 64;
    private static final int MAX_STEPS = 4000;
    private static final Set<String> ROOTS = Set.of(
            "org.springframework.security.access.expression.SecurityExpressionOperations",
            "org.springframework.security.access.expression.method.MethodSecurityExpressionOperations",
            "org.springframework.security.access.expression.SecurityExpressionRoot");
    private static final String AUTHENTICATION = "org.springframework.security.core.Authentication";
    private static final String SUPPLIER = "java.util.function.Supplier";
    private static final Set<String> DECISIONS = Set.of(
            "org.springframework.security.authorization.AuthorizationDecision",
            "org.springframework.security.authorization.AuthorityAuthorizationDecision");
    private static final String GRANTED_AUTHORITY = "org.springframework.security.core.authority.SimpleGrantedAuthority";
    private static final String REPOSITORY = "org.springframework.data.repository.Repository";
    private static final Set<String> STORES = Set.of("org.springframework.jdbc.core.JdbcTemplate",
            "org.springframework.jdbc.core.JdbcOperations",
            "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate",
            "org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations",
            "org.springframework.jdbc.core.simple.JdbcClient", "jakarta.persistence.EntityManager");
    private static final List<String> CLIENTS = List.of("org.springframework.web.client.RestClient",
            "org.springframework.web.client.RestTemplate", "org.springframework.web.client.RestOperations",
            "org.springframework.web.reactive.function.client.WebClient", "java.net.http.HttpClient");
    static final Set<String> DENIALS = Set.of("org.springframework.security.authorization.AuthorizationDeniedException",
            "org.springframework.security.access.AccessDeniedException");

    /**
     * What a decision method's body shows.
     *
     * @param requirement what it decides, empty when AuthTracer can't reduce it
     * @param reads the stores it reads ({@code OwnerRepository#findById}), which make what it decides Live
     * @param calls the clients it calls other services with
     * @param throwsDenial whether it denies by throwing {@code AuthorizationDeniedException} or
     *        {@code AccessDeniedException}
     */
    record Reading(Optional<Requirement> requirement, Set<String> reads, Set<String> calls, boolean throwsDenial) {
    }

    private sealed interface Sym {
    }

    private record Bool(boolean value) implements Sym {
    }

    /**
     * A boolean that is whether the caller meets the requirement.
     */
    private record Truth(Requirement requirement) implements Sym {
    }

    private record Decision(Sym granted) implements Sym {
    }

    private record Abstain() implements Sym {
    }

    private record Manager(Requirement requirement) implements Sym {
    }

    private record Auth() implements Sym {
    }

    private record AuthSupplier() implements Sym {
    }

    private record SecurityContext() implements Sym {
    }

    private record Root() implements Sym {
    }

    private record Authorities() implements Sym {
    }

    private record Authority(String name) implements Sym {
    }

    private record Text(String value) implements Sym {
    }

    /**
     * An array, as its elements are assigned: the strings or the managers it holds ({@code hasAnyRole("A", "B")},
     * {@code anyOf(hasRole("A"), hasRole("B"))}), and whether every element is one.
     */
    private record Array(List<Sym> values, boolean[] complete) implements Sym {
    }

    private record Mono(Sym value) implements Sym {
    }

    /**
     * An object created but not yet initialized: a decision, an authority.
     */
    private record Created(String type) implements Sym {
    }

    private record Unknown() implements Sym {
    }

    private static final Sym UNKNOWN = new Unknown();

    /**
     * The condition the walk can't read: the method is undecided.
     */
    private static final class Undecided extends RuntimeException {
        Undecided() {
            super(null, null, false, false);
        }
    }

    private final ScanContext context;
    private final JavaSootMethod method;
    private final ControlFlowGraph<?> graph;
    private final Set<String> reads = new LinkedHashSet<>();
    private final Set<String> calls = new LinkedHashSet<>();
    private final List<List<Requirement>> granting = new ArrayList<>();
    private boolean throwsDenial;
    private int paths;
    private int steps;

    private DecisionBodies(ScanContext context, JavaSootMethod method) {
        this.context = context;
        this.method = method;
        this.graph = method.getBody().getControlFlowGraph();
    }

    static Reading read(ScanContext context, JavaSootMethod method) {
        DecisionBodies bodies = new DecisionBodies(context, method);
        Optional<Requirement> requirement;
        try {
            bodies.recordReads();
            if (bodies.graph.getNodes().stream().anyMatch(stmt -> !bodies.graph.exceptionalSuccessors(stmt)
                    .isEmpty())) {
                // A catch block may grant what the try block denies.
                throw new Undecided();
            }
            bodies.walk(bodies.graph.getStartingStmt(), new HashMap<>(), new ArrayList<>(), new HashMap<>());
            requirement = Optional.of(bodies.combined());
        }
        catch (Undecided undecided) {
            requirement = Optional.empty();
        }
        return new Reading(requirement, bodies.reads, bodies.calls, bodies.throwsDenial);
    }

    /**
     * The stores and clients the method calls, on any path.
     */
    private void recordReads() {
        // In statement order: the graph's nodes come in no fixed order, and the finding should be the same every scan.
        for (Stmt stmt : method.getBody().getStmts()) {
            if (!stmt.isInvokableStmt()) {
                continue;
            }
            stmt.asInvokableStmt().getInvokeExpr().ifPresent(invoke -> {
                ClassType owner = invoke.getMethodSignature().getDeclClassType();
                String called = MethodNames.simpleName(owner.getFullyQualifiedName()) + "#"
                        + invoke.getMethodSignature().getName();
                if (STORES.contains(owner.getFullyQualifiedName()) || context.isApplication(owner)
                        && SpringBeans.assignable(context, owner, Set.of(REPOSITORY))) {
                    reads.add(called);
                }
                if (CLIENTS.stream().anyMatch(client -> owner.getFullyQualifiedName().startsWith(client))) {
                    calls.add(called);
                }
            });
        }
    }

    private void walk(Stmt start, Map<Local, Sym> entry, List<Requirement> conditions, Map<Stmt, Integer> visits) {
        if (++paths > MAX_PATHS) {
            throw new Undecided();
        }
        Map<Local, Sym> values = new HashMap<>(entry);
        Map<Stmt, Integer> seen = new HashMap<>(visits);
        Stmt stmt = start;
        while (true) {
            if (++steps > MAX_STEPS || seen.merge(stmt, 1, Integer::sum) > 1) {
                // A loop: what it decides depends on how often it runs.
                throw new Undecided();
            }
            if (stmt instanceof JReturnStmt returned) {
                grant(conditions, outcome(value(returned.getOp(), values)));
                return;
            }
            if (stmt instanceof JThrowStmt thrown) {
                throwsDenial |= thrown.getOp() instanceof Local local && values.get(local) instanceof Created created
                        && DENIALS.contains(created.type());
                return;
            }
            if (stmt instanceof JIfStmt branch) {
                List<Stmt> next = graph.successors(stmt);
                Optional<Boolean> known = known(branch.getCondition(), values);
                if (known.isPresent()) {
                    stmt = next.get(known.get() ? JIfStmt.TRUE_BRANCH_IDX : JIfStmt.FALSE_BRANCH_IDX);
                    continue;
                }
                Requirement condition = condition(branch.getCondition(), values);
                List<Requirement> taken = new ArrayList<>(conditions);
                taken.add(condition);
                walk(next.get(JIfStmt.TRUE_BRANCH_IDX), values, taken, seen);
                List<Requirement> skipped = new ArrayList<>(conditions);
                skipped.add(negate(condition));
                walk(next.get(JIfStmt.FALSE_BRANCH_IDX), values, skipped, seen);
                return;
            }
            if (stmt instanceof AbstractDefinitionStmt definition) {
                assign(definition, values);
            }
            else if (stmt.isInvokableStmt()) {
                stmt.asInvokableStmt().getInvokeExpr().ifPresent(invoke -> initialize(invoke, values));
            }
            List<Stmt> next = graph.successors(stmt);
            if (next.size() != 1 || !(stmt instanceof JGotoStmt) && !stmt.fallsThrough()) {
                // A switch, a return without a value: not a decision AuthTracer reads.
                throw new Undecided();
            }
            stmt = next.getFirst();
        }
    }

    private void assign(AbstractDefinitionStmt definition, Map<Local, Sym> values) {
        Value right = definition.getRightOp();
        if (definition.getLeftOp() instanceof JArrayRef element) {
            if (values.get(element.getBase()) instanceof Array array) {
                Sym value = value(right, values);
                if (value instanceof Text || value instanceof Manager) {
                    array.values().add(value);
                }
                else {
                    array.complete()[0] = false;
                }
            }
            return;
        }
        if (definition.getLeftOp() instanceof Local local) {
            values.put(local, evaluate(right, values));
        }
    }

    private Sym evaluate(Value right, Map<Local, Sym> values) {
        if (right instanceof JParameterRef parameter) {
            return parameter(method.getParameterType(parameter.getIndex()));
        }
        if (right instanceof JCastExpr cast) {
            return value(cast.getOp(), values);
        }
        if (right instanceof JNewArrayExpr) {
            return new Array(new ArrayList<>(), new boolean[] {true});
        }
        if (right instanceof JNewExpr created) {
            return new Created(created.getType().getFullyQualifiedName());
        }
        if (right instanceof JStaticFieldRef field && field.getFieldSignature().getDeclClassType()
                .getFullyQualifiedName().equals("java.lang.Boolean")) {
            return new Bool(field.getFieldSignature().getName().equals("TRUE"));
        }
        if (right instanceof AbstractInvokeExpr invoke) {
            return call(invoke, values);
        }
        return value(right, values);
    }

    private Sym parameter(Type type) {
        if (!(type instanceof ClassType classType)) {
            return UNKNOWN;
        }
        String name = classType.getFullyQualifiedName();
        if (name.equals(SUPPLIER)) {
            return new AuthSupplier();
        }
        if (ROOTS.contains(name)) {
            return new Root();
        }
        return SpringBeans.assignable(context, classType, Set.of(AUTHENTICATION)) ? new Auth() : UNKNOWN;
    }

    private Sym call(AbstractInvokeExpr invoke, Map<Local, Sym> values) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        List<Sym> args = invoke.getArgs().stream().map(arg -> value(arg, values)).toList();
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance)) {
            return switch (owner) {
                case "org.springframework.security.core.context.SecurityContextHolder" ->
                        name.equals("getContext") ? new SecurityContext() : UNKNOWN;
                case "org.springframework.security.core.authority.AuthorityUtils" ->
                        name.equals("authorityListToSet") && args.getFirst() instanceof Authorities ? new Authorities()
                                : UNKNOWN;
                case "java.lang.Boolean" -> name.equals("valueOf") ? args.getFirst() : UNKNOWN;
                case "reactor.core.publisher.Mono" -> name.equals("just") ? new Mono(args.getFirst()) : UNKNOWN;
                default -> BuiltInManagers.factory(owner, name, invoke.getMethodSignature().getParameterTypes()
                        .stream().map(Object::toString).toList(), managerArgs(args))
                        .map(requirement -> (Sym) new Manager(requirement)).orElse(UNKNOWN);
            };
        }
        Sym receiver = value(instance.getBase(), values);
        return switch (receiver) {
            case AuthSupplier ignored when name.equals("get") -> new Auth();
            case SecurityContext ignored when name.equals("getAuthentication") -> new Auth();
            case Auth ignored when name.equals("getAuthorities") -> new Authorities();
            case Root ignored when name.equals("getAuthentication") -> new Auth();
            case Root ignored -> BuiltInManagers.named(rootName(name), managerArgs(args), BuiltInManagers.ROLE_PREFIX)
                    .map(requirement -> (Sym) new Truth(requirement)).orElse(UNKNOWN);
            case Authorities ignored when name.equals("contains") && args.size() == 1 -> switch (args.getFirst()) {
                case Authority authority -> new Truth(Requirement.anyAuthority(List.of(authority.name())));
                case Text text -> new Truth(Requirement.anyAuthority(List.of(text.value())));
                default -> UNKNOWN;
            };
            case Manager manager when name.equals("authorize") || name.equals("check") ->
                    new Decision(new Truth(manager.requirement()));
            case Decision decision when name.equals("isGranted") -> decision.granted();
            case Bool bool when name.equals("booleanValue") -> bool;
            case Truth truth when name.equals("booleanValue") -> truth;
            default -> UNKNOWN;
        };
    }

    /**
     * The root's {@code isAuthenticated()} is the managers' {@code authenticated()}, and so on.
     */
    private static String rootName(String name) {
        return switch (name) {
            case "isAuthenticated" -> "authenticated";
            case "isFullyAuthenticated" -> "fullyAuthenticated";
            case "isRememberMe" -> "rememberMe";
            case "isAnonymous" -> "anonymous";
            default -> name;
        };
    }

    /**
     * {@code new AuthorizationDecision(granted)}, {@code new SimpleGrantedAuthority("ROLE_X")}.
     */
    private void initialize(AbstractInvokeExpr invoke, Map<Local, Sym> values) {
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance) || !invoke.getMethodSignature().getName()
                .equals("<init>") || !(values.get(instance.getBase()) instanceof Created created)
                || invoke.getArgCount() == 0) {
            return;
        }
        Sym first = value(invoke.getArg(0), values);
        if (DECISIONS.contains(created.type())) {
            values.put(instance.getBase(), new Decision(first));
        }
        else if (created.type().equals(GRANTED_AUTHORITY) && first instanceof Text text) {
            values.put(instance.getBase(), new Authority(text.value()));
        }
    }

    private static List<BuiltInManagers.Arg> managerArgs(List<Sym> args) {
        return args.stream().map(arg -> switch (arg) {
            case Text text -> (BuiltInManagers.Arg) new BuiltInManagers.Text(text.value());
            case Array array when !array.values().isEmpty()
                    && array.values().stream().allMatch(Manager.class::isInstance) -> new BuiltInManagers.Managers(
                            array.values().stream().map(manager -> ((Manager) manager).requirement()).toList(),
                            array.complete()[0]);
            case Array array -> new BuiltInManagers.Texts(array.values().stream().filter(Text.class::isInstance)
                    .map(text -> ((Text) text).value()).toList(), array.complete()[0]
                            && array.values().stream().allMatch(Text.class::isInstance));
            case Manager manager -> new BuiltInManagers.Manager(manager.requirement());
            default -> BuiltInManagers.UNKNOWN;
        }).toList();
    }

    private static Sym value(Value value, Map<Local, Sym> values) {
        if (value instanceof StringConstant constant) {
            return new Text(constant.getValue());
        }
        if (value instanceof IntConstant constant) {
            return new Bool(constant.getValue() != 0);
        }
        if (value instanceof NullConstant) {
            return new Abstain();
        }
        return value instanceof Local local ? values.getOrDefault(local, UNKNOWN) : UNKNOWN;
    }

    /**
     * What a returned value grants: a requirement, {@code permitAll} for a constant grant or an abstention,
     * {@code denyAll} for a constant denial.
     */
    private static Requirement outcome(Sym returned) {
        return switch (returned) {
            case Bool bool -> bool.value() ? Requirement.permitAll() : Requirement.denyAll();
            case Truth truth -> truth.requirement();
            case Decision decision -> outcome(decision.granted());
            case Abstain ignored -> Requirement.permitAll();
            case Manager manager -> manager.requirement();
            case Mono mono -> outcome(mono.value());
            default -> throw new Undecided();
        };
    }

    /**
     * A branch the walk knows the way of: a constant, or an object that is never {@code null} (the Authentication a
     * check is given).
     */
    private static Optional<Boolean> known(AbstractConditionExpr condition, Map<Local, Sym> values) {
        if (!(condition instanceof JEqExpr) && !(condition instanceof JNeExpr)) {
            throw new Undecided();
        }
        boolean equal = condition instanceof JEqExpr;
        Sym left = value(condition.getOp1(), values);
        Sym right = value(condition.getOp2(), values);
        if (condition.getOp2() instanceof NullConstant) {
            boolean isNull = switch (left) {
                case Auth ignored -> false;
                case Authorities ignored -> false;
                case Decision ignored -> false;
                case Abstain ignored -> true;
                default -> throw new Undecided();
            };
            return Optional.of(equal == isNull);
        }
        if (left instanceof Bool first && right instanceof Bool second) {
            return Optional.of(equal == (first.value() == second.value()));
        }
        return Optional.empty();
    }

    /**
     * The requirement a branch is taken on: {@code if (z == 0)} on a check's result is its negation.
     */
    private static Requirement condition(AbstractConditionExpr condition, Map<Local, Sym> values) {
        Sym left = value(condition.getOp1(), values);
        if (!(left instanceof Truth truth) || !(condition.getOp2() instanceof IntConstant constant)
                || constant.getValue() != 0) {
            throw new Undecided();
        }
        return condition instanceof JNeExpr ? truth.requirement() : negate(truth.requirement());
    }

    private static Requirement negate(Requirement requirement) {
        return requirement.kind() == Requirement.Kind.NOT ? requirement.operands().getFirst()
                : Requirement.not(requirement);
    }

    private void grant(List<Requirement> conditions, Requirement outcome) {
        if (outcome.kind() == Requirement.Kind.DENY_ALL) {
            return;
        }
        List<Requirement> way = new ArrayList<>(conditions);
        if (outcome.kind() != Requirement.Kind.PERMIT_ALL) {
            way.add(outcome);
        }
        // A way that asks for something and its negation is never taken.
        if (way.stream().noneMatch(term -> way.contains(negate(term)) && !negate(term).equals(term))) {
            granting.add(way);
        }
    }

    /**
     * The {@code or} of the granting ways. {@code a || b} compiles to the ways {@code a} and {@code !a && b}: a
     * negation another way grants on its own is dropped, which is exact here.
     */
    private Requirement combined() {
        List<List<Requirement>> ways = new ArrayList<>();
        for (List<Requirement> way : granting) {
            List<Requirement> kept = way.stream().filter(term -> term.kind() != Requirement.Kind.NOT
                    || !granting.contains(List.of(term.operands().getFirst()))).distinct().toList();
            if (!ways.contains(kept)) {
                ways.add(kept);
            }
        }
        if (ways.isEmpty()) {
            return Requirement.denyAll();
        }
        if (ways.stream().anyMatch(List::isEmpty)) {
            return Requirement.permitAll();
        }
        List<Requirement> alternatives = ways.stream()
                .map(way -> way.size() == 1 ? way.getFirst() : Requirement.and(way)).distinct().toList();
        return alternatives.size() == 1 ? alternatives.getFirst() : Requirement.or(alternatives);
    }
}
