package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher.Test;
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
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JGotoStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.JNopStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootMethod;

/**
 * HTTP-06: a {@code RequestMatcher} lambda, or a method reference to a predicate such as
 * {@code CorsUtils::isPreFlightRequest}, read for what it tests, when all it does is compare the request's method,
 * servlet path, raw URI, headers or parameters with constants (and call predicates that do the same). Each way to
 * {@code return true} is an alternative whose tests must all hold. Anything else it reads or does (the caller's
 * address, a bean, a field) leaves it unread: decision 0051's matcher that may match.
 */
@Supports(Feature.REQUEST_RULES)
final class MatcherLambdas {

    private static final String REQUEST = "jakarta.servlet.http.HttpServletRequest";
    private static final String HTTP_METHOD = "org.springframework.http.HttpMethod";
    private static final int MAX_DEPTH = 3;
    private static final int MAX_STEPS = 400;
    private static final int MAX_ALTERNATIVES = 16;
    private static final List<List<Test>> TRUE = List.of(List.of());
    private static final List<List<Test>> FALSE = List.of();

    private sealed interface Sym {
    }

    private record Request() implements Sym {
    }

    private record Text(String value) implements Sym {
    }

    private record Number(int value) implements Sym {
    }

    private record Null() implements Sym {
    }

    /**
     * An {@code HttpMethod} constant.
     */
    private record Method(String name) implements Sym {
    }

    /**
     * A string the request gives: its servlet path, raw URI, method, or a named header or parameter.
     */
    private record Read(Source source, String name) implements Sym {
    }

    private enum Source {
        PATH, URI, METHOD, HEADER, PARAMETER
    }

    /**
     * A boolean, as alternatives each of whose tests must hold.
     */
    private record Flag(List<List<Test>> alternatives) implements Sym {
    }

    private record State(Stmt stmt, Map<Local, Sym> values, List<List<Test>> condition) {
    }

    /**
     * The result is too large or reads something else.
     */
    private static final class Unread extends RuntimeException {

        Unread() {
            super(null, null, false, false);
        }
    }

    private final ScanContext context;
    private final boolean servletPathKnown;
    private final boolean uriKnown;

    private MatcherLambdas(ScanContext context, String servletPath) {
        this.context = context;
        // getServletPath() is the whole path only for a DispatcherServlet on "/"; the raw URI has the context path.
        this.servletPathKnown = servletPath.isEmpty();
        this.uriKnown = context.properties().get("server.servlet.context-path")
                .filter(path -> !path.isEmpty() && !path.equals("/")).isEmpty();
    }

    /**
     * @param captured the constants the lambda captures, one per parameter before the request ({@code null} for one
     *        that isn't a constant)
     * @param servletPath the DispatcherServlet's path, empty for {@code /}
     */
    static Optional<Matcher> read(ScanContext context, MethodSignature lambda, List<String> captured,
            String servletPath) {
        List<Sym> arguments = new ArrayList<>(captured.stream().map(value -> value == null ? null
                : (Sym) new Text(value)).toList());
        arguments.add(new Request());
        try {
            // Sorted, so the description doesn't depend on the order the branches were walked in.
            return new MatcherLambdas(context, servletPath).evaluate(lambda, arguments, 0)
                    .map(alternatives -> alternatives.stream().sorted(Comparator.comparing(
                            tests -> tests.stream().map(Test::describe).toList().toString())).toList())
                    .map(Matcher::tests);
        }
        catch (Unread unread) {
            return Optional.empty();
        }
    }

    /**
     * What a predicate on the request returns, empty when it isn't one.
     */
    private Optional<List<List<Test>>> evaluate(MethodSignature signature, List<Sym> arguments, int depth) {
        Optional<JavaSootMethod> method = context.findMethod(signature).filter(JavaSootMethod::hasBody);
        // The request is the lambda's last parameter, and wherever a helper the lambda calls takes it:
        // under(request, "/admin").
        if (method.isEmpty() || depth > MAX_DEPTH || !signature.getType().toString().equals("boolean")
                || signature.getParameterCount() != arguments.size()
                || !signature.getParameterTypes().get(arguments.indexOf(new Request())).toString().equals(REQUEST)) {
            return Optional.empty();
        }
        ControlFlowGraph<?> graph = method.get().getBody().getControlFlowGraph();
        Deque<State> work = new ArrayDeque<>(List.of(new State(graph.getStartingStmt(), new HashMap<>(), TRUE)));
        List<List<Test>> result = FALSE;
        int steps = 0;
        while (!work.isEmpty()) {
            State state = work.pop();
            if (++steps > MAX_STEPS) {
                throw new Unread();
            }
            Stmt stmt = state.stmt();
            Map<Local, Sym> values = state.values();
            switch (stmt) {
                case JIdentityStmt identity -> {
                    if (identity.getRightOp() instanceof JParameterRef parameter
                            && arguments.get(parameter.getIndex()) != null) {
                        values.put(identity.getLeftOp(), arguments.get(parameter.getIndex()));
                    }
                }
                case JAssignStmt assign when assign.getLeftOp() instanceof Local local -> {
                    Sym value = value(assign.getRightOp(), values, depth);
                    if (value == null) {
                        values.remove(local);
                    }
                    else {
                        values.put(local, value);
                    }
                }
                case JIfStmt branch -> {
                    List<List<Test>> holds = condition(branch.getCondition(), values);
                    List<Stmt> next = graph.successors(branch);
                    fork(work, next.get(JIfStmt.TRUE_BRANCH_IDX), values, and(state.condition(), holds));
                    fork(work, next.get(JIfStmt.FALSE_BRANCH_IDX), values, and(state.condition(), not(holds)));
                    continue;
                }
                case JReturnStmt returned -> {
                    result = or(result, and(state.condition(), flag(sym(returned.getOp(), values))));
                    continue;
                }
                case JGotoStmt jump -> {
                }
                case JInvokeStmt call -> {
                    // A call whose result is dropped (a log line) decides nothing.
                }
                case JNopStmt nop -> {
                }
                default -> throw new Unread();
            }
            work.push(new State(graph.successors(stmt).getFirst(), values, state.condition()));
        }
        return Optional.of(result);
    }

    private static void fork(Deque<State> work, Stmt next, Map<Local, Sym> values, List<List<Test>> condition) {
        if (!condition.isEmpty()) {
            work.push(new State(next, new HashMap<>(values), condition));
        }
    }

    private static Sym sym(Value value, Map<Local, Sym> values) {
        return switch (value) {
            case Local local -> values.get(local);
            case StringConstant constant -> new Text(constant.getValue());
            case IntConstant constant -> new Number(constant.getValue());
            case NullConstant constant -> new Null();
            default -> null;
        };
    }

    private Sym value(Value value, Map<Local, Sym> values, int depth) {
        return switch (value) {
            case JStaticFieldRef field when field.getFieldSignature().getDeclClassType().getFullyQualifiedName()
                    .equals(HTTP_METHOD) -> new Method(field.getFieldSignature().getName());
            case JCastExpr cast -> sym(cast.getOp(), values);
            case AbstractInvokeExpr invoke -> invoke(invoke, values, depth);
            default -> sym(value, values);
        };
    }

    private Sym invoke(AbstractInvokeExpr invoke, Map<Local, Sym> values, int depth) {
        Sym receiver = invoke instanceof AbstractInstanceInvokeExpr instance ? values.get(instance.getBase()) : null;
        List<Sym> arguments = invoke.getArgs().stream().map(arg -> sym(arg, values)).toList();
        String name = invoke.getMethodSignature().getName();
        Optional<String> text = arguments.size() == 1 && arguments.getFirst() instanceof Text constant
                ? Optional.of(constant.value()) : Optional.empty();
        if (receiver instanceof Request) {
            return switch (name) {
                case "getServletPath" -> servletPathKnown ? new Read(Source.PATH, null) : null;
                case "getRequestURI" -> uriKnown ? new Read(Source.URI, null) : null;
                case "getMethod" -> new Read(Source.METHOD, null);
                case "getHeader" -> text.map(header -> new Read(Source.HEADER, header)).orElse(null);
                case "getParameter" -> text.map(parameter -> new Read(Source.PARAMETER, parameter)).orElse(null);
                default -> null;
            };
        }
        if (receiver instanceof Read read && text.isPresent()) {
            return compare(read, name, text.get(), false);
        }
        if (receiver instanceof Text constant && arguments.size() == 1 && arguments.getFirst() instanceof Read read) {
            // "/admin".equals(path) is path.equals("/admin"); "/admin/reports".startsWith(path) asks whether the path
            // is a start of the constant.
            return compare(read, name, constant.value(), true);
        }
        if (receiver instanceof Method method && name.equals("matches")
                && arguments.equals(List.of(new Read(Source.METHOD, null)))) {
            return flag(new Test(Test.Kind.METHOD, method.name(), false));
        }
        if (receiver == null && arguments.contains(new Request())) {
            // A predicate the lambda calls with the request: CorsUtils.isPreFlightRequest(request).
            return evaluate(invoke.getMethodSignature(), arguments, depth + 1).map(Flag::new).orElse(null);
        }
        // Any other test of a header or parameter, e.g. StringUtils.hasText(request.getHeader("X-Key")).
        return Stream.concat(Stream.ofNullable(receiver), arguments.stream())
                .filter(Read.class::isInstance).map(Read.class::cast).filter(MatcherLambdas::callerSends)
                .filter(read -> invoke.getMethodSignature().getType().toString().equals("boolean")).findFirst()
                .map(read -> (Sym) flag(callerTest(read, false))).orElse(null);
    }

    /**
     * A string the request gives compared with a constant: {@code startsWith}, {@code equals},
     * {@code equalsIgnoreCase} on the path, URI or method; anything the caller sends, any test.
     */
    private static Sym compare(Read read, String name, String constant, boolean reversed) {
        if (callerSends(read)) {
            return flag(callerTest(read, false));
        }
        boolean equals = name.equals("equals") || name.equals("equalsIgnoreCase");
        boolean startsWith = name.equals("startsWith");
        boolean ignoringCase = name.equals("equalsIgnoreCase");
        String value = ignoringCase && read.source() == Source.METHOD ? constant.toUpperCase(java.util.Locale.ROOT)
                : constant;
        Test.Kind kind = switch (read.source()) {
            case METHOD -> equals ? Test.Kind.METHOD : null;
            // Paths compare case-sensitively: /OPS is another path, which equalsIgnoreCase lets through too.
            case PATH -> ignoringCase ? Test.Kind.PATH_IGNORING_CASE : equals ? Test.Kind.PATH
                    : startsWith ? reversed ? Test.Kind.PATH_START_OF : Test.Kind.PATH_PREFIX : null;
            default -> equals && !ignoringCase ? Test.Kind.URI : startsWith && !reversed ? Test.Kind.URI_PREFIX
                    : null;
        };
        return kind == null ? null : flag(new Test(kind, value, false));
    }

    private static boolean callerSends(Read read) {
        return read.source() == Source.HEADER || read.source() == Source.PARAMETER;
    }

    private static Test callerTest(Read read, boolean negated) {
        return new Test(read.source() == Source.HEADER ? Test.Kind.HEADER : Test.Kind.PARAMETER, read.name(),
                negated);
    }

    /**
     * {@code flag == 0}, {@code flag != 0}, {@code header == null}, {@code header != null}.
     */
    private static List<List<Test>> condition(AbstractConditionExpr condition, Map<Local, Sym> values) {
        Sym left = sym(condition.getOp1(), values);
        Sym right = sym(condition.getOp2(), values);
        boolean equal = condition instanceof JEqExpr;
        if (!equal && !(condition instanceof JNeExpr)) {
            throw new Unread();
        }
        if (left instanceof Flag flag && right instanceof Number zero && zero.value() == 0) {
            return equal ? not(flag.alternatives()) : flag.alternatives();
        }
        if (left instanceof Read read && right instanceof Null && callerSends(read)) {
            return List.of(List.of(callerTest(read, equal)));
        }
        throw new Unread();
    }

    private static Flag flag(Test test) {
        return new Flag(List.of(List.of(test)));
    }

    private static List<List<Test>> flag(Sym returned) {
        return switch (returned) {
            case Flag flag -> flag.alternatives();
            case Number number when number.value() == 0 -> FALSE;
            case Number number when number.value() == 1 -> TRUE;
            case null, default -> throw new Unread();
        };
    }

    private static List<List<Test>> and(List<List<Test>> left, List<List<Test>> right) {
        List<List<Test>> result = new ArrayList<>();
        for (List<Test> one : left) {
            for (List<Test> other : right) {
                Set<Test> both = new LinkedHashSet<>(one);
                both.addAll(other);
                if (both.stream().noneMatch(test -> both.contains(test.not()))) {
                    result.add(List.copyOf(both));
                }
            }
        }
        return bounded(result);
    }

    private static List<List<Test>> or(List<List<Test>> left, List<List<Test>> right) {
        List<List<Test>> both = new ArrayList<>(new LinkedHashSet<>(left));
        right.stream().filter(tests -> !both.contains(tests)).forEach(both::add);
        return bounded(both.contains(List.of()) ? new ArrayList<>(TRUE) : simplified(both));
    }

    /**
     * The alternatives as a branch on {@code a || b} leaves them, {@code a} or {@code !a && b}, read back as
     * {@code a} or {@code b}; an alternative that asks more than another is dropped.
     */
    private static List<List<Test>> simplified(List<List<Test>> alternatives) {
        List<List<Test>> result = new ArrayList<>(alternatives);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (int i = 0; i < result.size() && !changed; i++) {
                for (int j = 0; j < result.size() && !changed; j++) {
                    List<Test> one = result.get(i);
                    List<Test> other = result.get(j);
                    if (i != j && other.containsAll(one)) {
                        result.remove(j);
                        changed = true;
                    }
                    else if (i != j) {
                        for (Test test : one) {
                            List<Test> rest = new ArrayList<>(one);
                            rest.remove(test);
                            if (other.contains(test.not()) && other.containsAll(rest)) {
                                List<Test> resolved = new ArrayList<>(other);
                                resolved.remove(test.not());
                                result.set(j, List.copyOf(resolved));
                                changed = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        return result;
    }

    private static List<List<Test>> not(List<List<Test>> alternatives) {
        List<List<Test>> result = TRUE;
        for (List<Test> tests : alternatives) {
            result = and(result, tests.stream().map(test -> List.of(test.not())).toList());
        }
        return result;
    }

    private static List<List<Test>> bounded(List<List<Test>> alternatives) {
        if (alternatives.size() > MAX_ALTERNATIVES) {
            throw new Unread();
        }
        return alternatives;
    }
}
