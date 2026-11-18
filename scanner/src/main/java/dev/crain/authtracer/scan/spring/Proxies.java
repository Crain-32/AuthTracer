package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.ProxyFactories.Factory;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JThisRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0014: which values on a request path are authorization proxies, so that a field check counts only where
 * its getter is called on one. A value is a proxy when it is returned by an {@code @AuthorizeReturnObject} method
 * called through Spring's proxy (on a bean, not on {@code this}) or on a proxy; returned by
 * {@code AuthorizationProxyFactory#proxy}; an element of a proxied collection, optional, stream or array (Spring
 * proxies them element by element); a parameter its caller passed a proxy for; or returned by an application method
 * that returns one. A local counts only when every definition of it is a proxy, so the graph never overstates
 * protection. Decision 0088: each proxy carries the factory that made it, which decides the checks it runs; a value
 * that may come from more than one factory runs what they all apply.
 */
@Supports({Feature.FIELD_CHECKS, Feature.METHOD_SECURITY})
final class Proxies {

    /**
     * The receiver, among a call's arguments or a method's parameters.
     */
    static final int RECEIVER = -1;

    /**
     * Library calls on a proxied container that hand out its elements, or a container of them.
     */
    private static final Set<String> ELEMENTS = Set.of("get", "getFirst", "getLast", "next", "previous", "iterator",
            "listIterator", "stream", "parallelStream", "orElse", "orElseThrow", "orElseGet", "findFirst", "findAny",
            "toList", "collect", "filter", "sorted", "distinct", "limit", "skip", "peek", "values", "subList",
            "element", "poll", "pop", "min", "max", "reversed", "takeWhile", "dropWhile");
    /**
     * Library calls that wrap their arguments, a proxy among them: {@code ResponseEntity.ok(proxy)},
     * {@code List.of(proxy)}, {@code Mono.just(proxy)}.
     */
    private static final Set<String> WRAPPERS = Set.of("ok", "of", "ofNullable", "just", "justOrEmpty", "body",
            "singletonList", "singleton", "copyOf", "asList", "unmodifiableList", "unmodifiableCollection",
            "fromIterable");
    /**
     * Library calls on a proxied container that call a function with its elements.
     */
    private static final Set<String> CONSUMERS = Set.of("map", "flatMap", "forEach", "forEachOrdered", "filter",
            "anyMatch", "allMatch", "noneMatch", "peek", "ifPresent", "ifPresentOrElse", "removeIf", "sorted", "min",
            "max", "reduce", "takeWhile", "dropWhile", "mapToInt", "mapToLong", "mapToDouble", "mapMulti",
            "replaceAll");

    private final ScanContext context;
    private final MethodSecurity methodSecurity;
    private final ProxyFactories factories;
    private final CallTraversal resolver;
    private final Map<String, Frame> frames = new HashMap<>();
    private final Set<String> inProgress = new HashSet<>();

    Proxies(ScanContext context, MethodSecurity methodSecurity, ProxyFactories factories) {
        this.context = context;
        this.methodSecurity = methodSecurity;
        this.factories = factories;
        this.resolver = new CallTraversal(context);
    }

    /**
     * The method, entered with these parameters ({@link #RECEIVER} for {@code this}) holding proxies, each with the
     * factory that made it.
     */
    Frame frame(JavaSootMethod method, Map<Integer, Factory> proxied) {
        String key = MethodNames.key(method.getSignature()) + new TreeMap<>(proxied);
        Frame cached = frames.get(key);
        if (cached != null) {
            return cached;
        }
        if (!method.hasBody() || !inProgress.add(key)) {
            return new Frame(method, proxied, false);
        }
        try {
            Frame frame = new Frame(method, proxied, true);
            frames.put(key, frame);
            return frame;
        }
        finally {
            inProgress.remove(key);
        }
    }

    final class Frame {

        private final JavaSootMethod method;
        private final Map<Integer, Factory> parameters;
        private final Local thisLocal;
        private final Map<Local, Factory> proxies = new HashMap<>();
        /**
         * Lambdas and method references a proxied container calls with its elements, by the expression creating them.
         */
        private final Map<JDynamicInvokeExpr, Map<Integer, Factory>> elementFunctions = new IdentityHashMap<>();
        private Factory returned;

        private Frame(JavaSootMethod method, Map<Integer, Factory> parameters, boolean analyze) {
            this.method = method;
            this.parameters = Map.copyOf(parameters);
            this.thisLocal = method.isStatic() || !method.hasBody() ? null : method.getBody().getThisLocal();
            if (analyze) {
                analyze(method.getBody().getStmts());
            }
        }

        /**
         * The parameters of the called method that get a proxy from this call, with the factory that made it.
         */
        Map<Integer, Factory> proxiedArguments(AbstractInvokeExpr invoke) {
            if (invoke instanceof JDynamicInvokeExpr dynamic) {
                Map<Integer, Factory> lambda = new HashMap<>(elementFunctions.getOrDefault(dynamic, Map.of()));
                captured(dynamic).forEach((index, factory) -> lambda.merge(index, factory, Factory::and));
                return lambda;
            }
            Map<Integer, Factory> proxied = new HashMap<>();
            if (invoke instanceof AbstractInstanceInvokeExpr instance && isProxy(instance.getBase())) {
                proxied.put(RECEIVER, proxies.get(instance.getBase()));
            }
            for (int i = 0; i < invoke.getArgCount(); i++) {
                if (invoke.getArg(i) instanceof Local local && proxies.containsKey(local)) {
                    proxied.put(i, proxies.get(local));
                }
            }
            return proxied;
        }

        boolean returnsProxy() {
            return returned != null;
        }

        /**
         * The factory that made what the method returns, {@code null} unless every value it returns is a proxy.
         */
        Factory returned() {
            return returned;
        }

        /**
         * The factory that made the authorization proxy the method was called on, {@code null} when it wasn't called
         * on one.
         */
        Factory onProxy() {
            return parameters.get(RECEIVER);
        }

        private boolean isProxy(Immediate value) {
            return value instanceof Local local && proxies.containsKey(local);
        }

        private void analyze(List<Stmt> stmts) {
            Map<Local, List<Value>> definitions = new HashMap<>();
            for (Stmt stmt : stmts) {
                if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local local) {
                    definitions.computeIfAbsent(local, key -> new ArrayList<>()).add(definition.getRightOp());
                }
            }
            // Least fixpoint: a local joins once every definition of it is a proxy; its factory only narrows after.
            boolean grew = true;
            while (grew) {
                grew = false;
                for (Map.Entry<Local, List<Value>> local : definitions.entrySet()) {
                    Factory factory = all(local.getValue());
                    if (factory != null && !factory.equals(proxies.get(local.getKey()))) {
                        proxies.put(local.getKey(), factory);
                        grew = true;
                    }
                }
            }
            Map<Local, JDynamicInvokeExpr> functions = new HashMap<>();
            definitions.forEach((local, values) -> {
                if (values.size() == 1 && values.getFirst() instanceof JDynamicInvokeExpr dynamic) {
                    functions.put(local, dynamic);
                }
            });
            List<Value> results = new ArrayList<>();
            for (Stmt stmt : stmts) {
                if (stmt instanceof JReturnStmt result) {
                    results.add(result.getOp());
                }
                Locals.invoke(stmt).ifPresent(invoke -> elementCalls(invoke, functions));
            }
            returned = all(results);
        }

        /**
         * What made every one of the values, {@code null} unless each is a proxy.
         */
        private Factory all(List<? extends Value> values) {
            Factory all = null;
            for (Value value : values) {
                Factory one = proxyValue(value);
                if (one == null) {
                    return null;
                }
                all = all == null ? one : all.and(one);
            }
            return all;
        }

        /**
         * {@code proxiedList.stream().map(Mapper::from)}: the function gets the elements.
         */
        private void elementCalls(AbstractInvokeExpr invoke, Map<Local, JDynamicInvokeExpr> functions) {
            if (!(invoke instanceof AbstractInstanceInvokeExpr instance) || !isProxy(instance.getBase())
                    || context.isApplication(invoke.getMethodSignature().getDeclClassType())
                    || !CONSUMERS.contains(invoke.getMethodSignature().getName())) {
                return;
            }
            for (Immediate arg : invoke.getArgs()) {
                if (arg instanceof Local local && functions.containsKey(local)) {
                    JDynamicInvokeExpr dynamic = functions.get(local);
                    target(dynamic).ifPresent(target -> elementFunctions.put(dynamic, Map.of(element(target,
                            dynamic.getArgCount()), proxies.get(instance.getBase()))));
                }
            }
        }

        /**
         * The parameter that gets the element: after the captured values for a static target (a lambda body,
         * {@code Mapper::from}); the receiver for an unbound method reference ({@code Account::getIban}); after the
         * bound receiver and other captures otherwise.
         */
        private static int element(JavaSootMethod target, int captured) {
            if (target.isStatic()) {
                return captured;
            }
            return captured == 0 ? RECEIVER : captured - 1;
        }

        /**
         * Values a lambda captures come first among its target's parameters; for an instance target the first is the
         * receiver ({@code i - 1} is {@link #RECEIVER} for it).
         */
        private Map<Integer, Factory> captured(JDynamicInvokeExpr dynamic) {
            Map<Integer, Factory> proxied = new HashMap<>();
            boolean bound = target(dynamic).map(target -> !target.isStatic()).orElse(false);
            for (int i = 0; i < dynamic.getArgCount(); i++) {
                if (dynamic.getArg(i) instanceof Local local && proxies.containsKey(local)) {
                    proxied.put(bound ? i - 1 : i, proxies.get(local));
                }
            }
            return proxied;
        }

        private Optional<JavaSootMethod> target(JDynamicInvokeExpr dynamic) {
            for (Value argument : dynamic.getBootstrapArgs()) {
                if (argument instanceof MethodHandle handle && handle.isMethodRef()
                        && handle.getReferenceSignature() instanceof MethodSignature target) {
                    return context.findMethod(target);
                }
            }
            return Optional.empty();
        }

        /**
         * The factory that made the value, {@code null} when it isn't a proxy.
         */
        private Factory proxyValue(Value value) {
            if (value instanceof JParameterRef parameter) {
                return parameters.get(parameter.getIndex());
            }
            if (value instanceof JThisRef) {
                return parameters.get(RECEIVER);
            }
            if (value instanceof Local local) {
                return proxies.get(local);
            }
            if (value instanceof JCastExpr cast) {
                return cast.getOp() instanceof Local local ? proxies.get(local) : null;
            }
            if (value instanceof JArrayRef array) {
                return proxies.get(array.getBase());
            }
            if (value instanceof AbstractInvokeExpr invoke && !(invoke instanceof JDynamicInvokeExpr)) {
                return returnedProxy(invoke);
            }
            return null;
        }

        private Factory returnedProxy(AbstractInvokeExpr invoke) {
            if (MethodSecurity.isProxyCall(invoke)) {
                return factories.of(method, invoke);
            }
            Local receiver = invoke instanceof AbstractInstanceInvokeExpr instance ? instance.getBase() : null;
            Factory onReceiver = receiver == null ? null : proxies.get(receiver);
            String name = invoke.getMethodSignature().getName();
            if (!context.isApplication(invoke.getMethodSignature().getDeclClassType())) {
                if (onReceiver != null && ELEMENTS.contains(name)) {
                    return onReceiver;
                }
                return WRAPPERS.contains(name) ? all(invoke.getArgs().stream().filter(this::isProxy).toList())
                        : null;
            }
            // Spring's proxy runs on a call to a bean (not on this) or on an object it already proxied.
            boolean throughProxy = receiver != null && (onReceiver != null || !receiver.equals(thisLocal));
            Set<JavaSootMethod> targets = resolver.targets(invoke);
            if (targets.isEmpty()) {
                // An interface the application doesn't implement, e.g. a Spring Data repository.
                return throughProxy && methodSecurity.returnsAuthorizedObject(invoke.getMethodSignature())
                        ? factories.spring() : null;
            }
            Factory all = null;
            for (JavaSootMethod target : targets) {
                // A proxy's @AuthorizeReturnObject methods hand out proxies of the factory that made it.
                Factory one = onReceiver != null
                        ? methodSecurity.authorizesReturnObject(target, onReceiver) ? onReceiver : null
                        : throughProxy && methodSecurity.returnsAuthorizedObject(target) ? factories.spring() : null;
                if (one == null) {
                    one = frame(target, proxiedArguments(invoke)).returned();
                }
                if (one == null) {
                    return null;
                }
                all = all == null ? one : all.and(one);
            }
            return all;
        }
    }
}
