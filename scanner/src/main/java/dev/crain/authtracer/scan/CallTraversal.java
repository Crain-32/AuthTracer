package dev.crain.authtracer.scan;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JInterfaceInvokeExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.expr.JVirtualInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.MethodModifier;
import sootup.core.signatures.MethodSignature;
import sootup.core.signatures.MethodSubSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Walks application code from an entry method in statement order and collects ordered steps.
 * Library code is a leaf: only application methods are entered. The order is the order the code is written in; a
 * step reached through a call that doesn't run on every way its method returns is conditional (decision 0027), and
 * so is one reached through one of the beans a virtual call may dispatch to.
 */
@Supports(Feature.CALL_PATHS)
public final class CallTraversal {

    private static final int MAX_DEPTH = 40;

    private static final String EVENT_LISTENER = "org.springframework.context.event.EventListener";
    private static final String APPLICATION_LISTENER = "org.springframework.context.ApplicationListener";
    private static final String AROUND_CLOSURE = "org.aspectj.runtime.internal.AroundClosure";

    private final ScanContext context;
    private final Predicate<ClassType> bean;
    private final EnclosingMethods enclosing;
    private final Map<String, Branches> branches = new HashMap<>();
    /**
     * The application's event listeners, with the event type each takes.
     */
    private Map<JavaSootMethod, List<String>> listeners;

    public CallTraversal(ScanContext context) {
        this(context, type -> false);
    }

    /**
     * @param bean whether the application creates the class as a bean: a virtual call that more than one bean's
     *        method may answer runs one of them, so they are walked as alternatives
     */
    public CallTraversal(ScanContext context, Predicate<ClassType> bean) {
        this.context = context;
        this.bean = bean;
        this.enclosing = new EnclosingMethods(context);
    }

    /**
     * Turns what the walk visits into graph node ids. Methods return the ids of nodes reached at that point,
     * in order.
     */
    public interface Listener {

        /**
         * @param call the call that entered the method, {@code null} for the entry method
         * @param viaThis the method was called on {@code this}, so proxy-based interception does not apply
         */
        List<String> onEnter(JavaSootMethod method, AbstractInvokeExpr call, boolean viaThis, List<String> stack);

        List<String> onCallSite(JavaSootMethod caller, Stmt stmt, AbstractInvokeExpr invoke);

        List<String> onExit(JavaSootMethod method, boolean viaThis);

        /**
         * Decision 0027: the calls of a method (walked unconditionally) that don't run on every way it returns.
         *
         * @param branches for each way through the method to a normal return, the nodes reached through those calls
         *        on it, other than those every way reaches
         * @param conditional every node reached through those calls, other than those every way reaches
         * @return nodes to record after the method's calls, e.g. a Split location combining the branches
         */
        List<String> onBranches(JavaSootMethod method, List<List<String>> branches, List<String> conditional);

        /**
         * A virtual call that runs one of several beans' methods: each was walked as an alternative, its nodes
         * conditional.
         *
         * @param targets the methods it may run
         * @param reached for each target, the nodes reached through it
         * @return nodes to record at the call, e.g. a Split location asking for the weakest target's
         */
        List<String> onDispatch(JavaSootMethod caller, AbstractInvokeExpr call, List<JavaSootMethod> targets,
                List<List<String>> reached);

        /**
         * A call the walk doesn't follow because it is already {@code limit} calls deep: what the method does isn't
         * read.
         *
         * @return nodes to record at the call, e.g. an Opaque node
         */
        List<String> onTooDeep(JavaSootMethod method, AbstractInvokeExpr call, int limit);
    }

    /**
     * A node reached along the walk.
     *
     * @param via the methods from the entry to where the node was reached, outermost first
     * @param conditional reached only through calls that don't run on every way their method returns
     */
    public record Step(String nodeId, List<String> via, boolean conditional) {

        /**
         * A node every way through reaches, outside any method: an entry point's rule, a forward, a view's checks.
         */
        public static Step unconditional(String nodeId) {
            return new Step(nodeId, List.of(), false);
        }
    }

    /**
     * @param receiver the class of the object the entry method runs on, when it inherits the method (a controller
     *        whose handler is its base class's): calls on {@code this} run its methods
     */
    public List<Step> walk(MethodSignature entry, ClassType receiver, Listener listener) {
        Walk walk = new Walk(listener);
        context.findMethod(entry).ifPresent(method -> walk.visit(method, null, false, false,
                receiver != null ? receiver : method.getDeclaringClassType()));
        return List.copyOf(walk.steps.values());
    }

    private Branches branches(JavaSootMethod method) {
        return branches.computeIfAbsent(identity(method), key -> Branches.of(method));
    }

    /**
     * A method as the walk tells methods apart: by its full signature, so a bridge ({@code Object run()}) and the
     * method it bridges ({@code Account run()}) are two.
     */
    private static String identity(JavaSootMethod method) {
        return method.getSignature().toString();
    }

    private final class Walk {

        private final Listener listener;
        private final Map<String, Step> steps = new LinkedHashMap<>();
        /**
         * The methods being walked, outermost first, as {@link Step#via()} names them.
         */
        private final Deque<String> stack = new ArrayDeque<>();
        /**
         * The same methods by {@link #identity}: what a recursion check compares.
         */
        private final Deque<String> walking = new ArrayDeque<>();
        /**
         * The nodes reached while visiting each call being visited, innermost last.
         */
        private final Deque<List<String>> collectors = new ArrayDeque<>();
        /**
         * How many dispatch alternatives the walk is inside: what it reaches there is conditional.
         */
        private int alternatives;

        private Walk(Listener listener) {
            this.listener = listener;
        }

        /**
         * @param receiver the class of the object the method runs on, {@code null} when the walk can't tell: calls on
         *        {@code this} run that class's methods
         */
        private void visit(JavaSootMethod method, AbstractInvokeExpr call, boolean viaThis, boolean conditional,
                ClassType receiver) {
            String key = identity(method);
            if (walking.contains(key)) {
                return;
            }
            if (walking.size() >= MAX_DEPTH) {
                context.limit("The call walk", MAX_DEPTH, MethodNames.key(method.getSignature()));
                record(listener.onTooDeep(method, call, MAX_DEPTH), List.copyOf(stack), conditional);
                return;
            }
            walking.addLast(key);
            // Decision 0089 (amended): a lambda or closure is named by the method it is written in; called there, it
            // is no step of its own.
            String name = enclosing.key(method);
            boolean step = stack.isEmpty() || !stack.getLast().equals(name) || !enclosing.written(method);
            if (step) {
                stack.addLast(name);
            }
            List<String> via = List.copyOf(stack);
            // What the calls around this one have collected so far: what this method reaches only on some of its
            // ways is handed to them as its Split, not as the raw checks of each way.
            List<List<String>> outer = new ArrayList<>(collectors);
            List<Integer> outerSizes = outer.stream().map(List::size).toList();
            record(listener.onEnter(method, call, viaThis, via), via, conditional);
            if (method.hasBody()) {
                Branches branches = branches(method);
                Local thisLocal = method.isStatic() ? null : method.getBody().getThisLocal();
                // The calls that don't run on every return, with what they reached.
                Map<Stmt, List<String>> sometimes = new LinkedHashMap<>();
                Set<String> everyWay = new HashSet<>();
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty()) {
                        continue;
                    }
                    boolean always = branches.onEveryReturn(stmt);
                    List<String> reached = new ArrayList<>();
                    collectors.addLast(reached);
                    record(listener.onCallSite(method, stmt, invoke.get()), via, conditional || !always);
                    boolean onThis = thisLocal != null && (invoke.get() instanceof AbstractInstanceInvokeExpr instance
                            && instance.getBase().equals(thisLocal) || GroovyCalls.of(invoke.get())
                                    .filter(groovy -> groovy.receiver().equals(thisLocal)).isPresent());
                    call(method, invoke.get(), onThis, receiver, via, conditional || !always);
                    collectors.removeLast();
                    if (always) {
                        everyWay.addAll(reached);
                    }
                    else if (!reached.isEmpty()) {
                        sometimes.put(stmt, reached);
                    }
                }
                // What another call reaches on every way isn't one of the alternatives.
                sometimes.values().forEach(reached -> reached.removeAll(everyWay));
                sometimes.values().removeIf(List::isEmpty);
                if (!sometimes.isEmpty()) {
                    List<List<String>> ways = branches.alternatives(sometimes, () -> context.limit(
                            "Telling apart the ways through a method", Branches.MAX_ALTERNATIVES,
                            MethodNames.key(method.getSignature()))).stream()
                            .map(alternative -> (List<String>) new ArrayList<>(alternative)).toList();
                    List<String> split = listener.onBranches(method, ways, sometimes.values().stream()
                            .flatMap(List::stream).distinct().toList());
                    Set<String> someWays = new HashSet<>();
                    sometimes.values().forEach(someWays::addAll);
                    for (int i = 0; i < outer.size(); i++) {
                        List<String> collector = outer.get(i);
                        collector.subList(outerSizes.get(i), collector.size()).removeIf(someWays::contains);
                    }
                    record(split, via, conditional);
                }
            }
            record(listener.onExit(method, viaThis), via, conditional);
            if (step) {
                stack.removeLast();
            }
            walking.removeLast();
        }

        /**
         * A call: on {@code this} with a known receiver, the receiver's method; a virtual call more than one bean
         * may answer, one of them; otherwise every target the class hierarchy gives.
         */
        private void call(JavaSootMethod caller, AbstractInvokeExpr invoke, boolean onThis, ClassType receiver,
                List<String> via, boolean conditional) {
            boolean virtual = invoke instanceof JVirtualInvokeExpr || invoke instanceof JInterfaceInvokeExpr;
            if (onThis && receiver != null && virtual) {
                // The object the walk is on runs its own override, not every subclass's.
                Optional<JavaSootMethod> own = resolve(receiver, invoke.getMethodSignature().getSubSignature());
                if (own.isPresent()) {
                    visit(bridged(own.get()), invoke, true, conditional, receiver);
                    return;
                }
            }
            List<JavaSootMethod> called = targets(invoke).stream().map(CallTraversal.this::bridged).distinct()
                    .toList();
            Map<JavaSootMethod, Set<ClassType>> run = beanTargets(invoke);
            if (!run.isEmpty()) {
                // A target a bean runs: a recursion back to one already being walked adds nothing new.
                List<JavaSootMethod> live = run.keySet().stream().filter(target -> !walking.contains(identity(target)))
                        .toList();
                if (live.size() > 1) {
                    dispatch(caller, invoke, live, onThis, via, conditional, run);
                }
                else {
                    live.forEach(target -> visit(target, invoke, onThis, conditional, only(run.get(target))));
                }
                return;
            }
            ClassType callee = onThis ? receiver : null;
            for (JavaSootMethod target : called) {
                visit(target, invoke, onThis, conditional, invoke instanceof JSpecialInvokeExpr ? callee : null);
            }
        }

        /**
         * Each target walked on its own, as one of the alternatives the call may run; what they reach goes to the
         * listener, not to the calls around it, which get what the listener makes of it.
         */
        private void dispatch(JavaSootMethod caller, AbstractInvokeExpr invoke, List<JavaSootMethod> targets,
                boolean onThis, List<String> via, boolean conditional, Map<JavaSootMethod, Set<ClassType>> beans) {
            Deque<List<String>> around = new ArrayDeque<>(collectors);
            collectors.clear();
            alternatives++;
            List<List<String>> reached = new ArrayList<>();
            for (JavaSootMethod target : targets) {
                List<String> way = new ArrayList<>();
                collectors.addLast(way);
                visit(target, invoke, onThis, conditional, only(beans.get(target)));
                collectors.removeLast();
                reached.add(way);
            }
            alternatives--;
            collectors.addAll(around);
            if (reached.stream().anyMatch(way -> !way.isEmpty())) {
                record(listener.onDispatch(caller, invoke, targets, reached), via, conditional);
            }
        }

        /**
         * A node reached unconditionally anywhere is unconditional; it keeps its first place in the order.
         */
        private void record(List<String> nodeIds, List<String> via, boolean conditional) {
            boolean sometimes = conditional || alternatives > 0;
            for (String nodeId : nodeIds) {
                Step existing = steps.get(nodeId);
                if (existing == null || existing.conditional() && !sometimes) {
                    steps.put(nodeId, new Step(nodeId, via, sometimes));
                }
                collectors.forEach(collector -> collector.add(nodeId));
            }
        }
    }

    /**
     * For a virtual call on an application type, the methods the beans that may receive it run, each with the bean
     * classes that run it: a bean's own method, one it inherits, or an interface's default. A method every bean
     * overrides (a delegate interface's default) runs for none. Empty when no bean may receive the call, or for a
     * Groovy call, which is dynamic (an invokedynamic).
     */
    private Map<JavaSootMethod, Set<ClassType>> beanTargets(AbstractInvokeExpr invoke) {
        Map<JavaSootMethod, Set<ClassType>> run = new LinkedHashMap<>();
        if (!(invoke instanceof JVirtualInvokeExpr || invoke instanceof JInterfaceInvokeExpr)
                || !context.isApplication(invoke.getMethodSignature().getDeclClassType())) {
            return run;
        }
        ClassType declared = invoke.getMethodSignature().getDeclClassType();
        List<ClassType> receivers = new ArrayList<>(List.of(declared));
        receivers.addAll(context.subtypesOf(declared));
        for (ClassType type : receivers) {
            Optional<JavaSootClass> cls = context.findClass(type);
            if (!bean.test(type) || cls.isEmpty() || cls.get().isInterface() || cls.get().isAbstract()) {
                continue;
            }
            resolve(type, invoke.getMethodSignature().getSubSignature()).map(this::bridged)
                    .ifPresent(target -> run.computeIfAbsent(target, key -> new LinkedHashSet<>()).add(type));
        }
        return run;
    }

    /**
     * The one class, when there is one.
     */
    private static ClassType only(Set<ClassType> types) {
        return types.size() == 1 ? types.iterator().next() : null;
    }

    /**
     * The method an object of the class runs for the call: its own or a superclass's, else an interface's default.
     */
    private Optional<JavaSootMethod> resolve(ClassType type, MethodSubSignature subSignature) {
        Optional<JavaSootMethod> concrete = concreteImplementation(type, subSignature);
        if (concrete.isPresent()) {
            return concrete;
        }
        List<ClassType> interfaces = new ArrayList<>(context.interfacesOf(type));
        return interfaces.stream().filter(context::isApplication).map(context::findClass).flatMap(Optional::stream)
                .map(cls -> cls.getMethod(subSignature)).flatMap(Optional::stream)
                .filter(JavaSootMethod::isConcrete).findFirst();
    }

    /**
     * The method a javac bridge ({@code Object run()} for {@code Account run()}) calls: its body is that call.
     */
    private JavaSootMethod bridged(JavaSootMethod method) {
        if (!MethodModifier.isBridge(method.getModifiers()) || !method.hasBody()) {
            return method;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals(method.getName())
                    && !invoke.get().getMethodSignature().equals(method.getSignature())) {
                Optional<JavaSootMethod> target = context.findMethod(invoke.get().getMethodSignature())
                        .filter(JavaSootMethod::isConcrete)
                        .or(() -> concreteImplementation(invoke.get().getMethodSignature().getDeclClassType(),
                                invoke.get().getMethodSignature().getSubSignature()));
                if (target.isPresent()) {
                    return target.get();
                }
            }
        }
        return method;
    }

    /**
     * Application methods the invoke may reach: class-hierarchy dispatch for virtual calls, and the referenced
     * method for lambdas and method references.
     */
    public Set<JavaSootMethod> targets(AbstractInvokeExpr invoke) {
        Set<JavaSootMethod> targets = new LinkedHashSet<>();
        Optional<GroovyCalls.Call> groovy = GroovyCalls.of(invoke);
        if (groovy.isPresent()) {
            // A dynamic Groovy call: dispatched like a virtual call on the receiver's static type.
            GroovyCalls.target(context, groovy.get()).ifPresent(method -> {
                if (method.isConcrete()) {
                    targets.add(method);
                }
                if (!method.isStatic()) {
                    GroovyCalls.receiverClass(context, groovy.get()).ifPresent(receiver ->
                            overrides(receiver, method.getSignature().getSubSignature(), targets));
                }
            });
            return targets;
        }
        if (invoke instanceof JDynamicInvokeExpr dynamic) {
            for (Value argument : dynamic.getBootstrapArgs()) {
                if (argument instanceof MethodHandle handle && handle.isMethodRef()
                        && handle.getReferenceSignature() instanceof MethodSignature referenced
                        && context.isApplication(referenced.getDeclClassType())) {
                    context.findMethod(referenced).filter(JavaSootMethod::isConcrete).ifPresent(targets::add);
                }
            }
            return targets;
        }
        MethodSignature signature = invoke.getMethodSignature();
        ClassType declared = signature.getDeclClassType();
        if (signature.getName().equals("publishEvent") && declared.getFullyQualifiedName()
                .startsWith("org.springframework.context.") && invoke.getArgCount() == 1
                // A constant too: publishEvent("refreshed") runs the String listeners.
                && invoke.getArg(0).getType() instanceof ClassType eventType) {
            return listeners(eventType);
        }
        if (!context.isApplication(declared)) {
            context.outsidePackages(declared, MethodNames.key(signature));
            return targets;
        }
        if (invoke instanceof JStaticInvokeExpr || invoke instanceof JSpecialInvokeExpr) {
            concreteImplementation(declared, signature.getSubSignature()).ifPresent(targets::add);
            if (signature.getName().equals("<init>") && isClosure(declared, "groovy.lang.Closure")) {
                // A Groovy closure, like a lambda, is followed where it is created: its doCall is its body.
                context.findClass(declared).stream().flatMap(cls -> cls.getMethods().stream())
                        .filter(method -> method.getName().equals("doCall") && method.isConcrete())
                        .forEach(targets::add);
            }
            if (signature.getName().equals("<init>") && isClosure(declared, AROUND_CLOSURE)) {
                // ajc moves a woven method's code to an around body, which the aspect's advice runs through the
                // closure the woven method makes: followed where it is made, its run calls the body.
                context.findClass(declared).stream().flatMap(cls -> cls.getMethods().stream())
                        .filter(method -> method.getName().equals("run") && method.isConcrete())
                        .forEach(targets::add);
            }
            return targets;
        }
        concreteImplementation(declared, signature.getSubSignature()).ifPresent(targets::add);
        overrides(declared, signature.getSubSignature(), targets);
        if (targets.isEmpty()) {
            // An application interface nothing in the application implements, e.g. a Spring Data repository: its
            // implementation is generated, and the interface method's own annotations apply.
            context.findClass(declared).filter(JavaSootClass::isInterface)
                    .flatMap(cls -> cls.getMethod(signature.getSubSignature())).ifPresent(targets::add);
        }
        return targets;
    }

    /**
     * {@code publisher.publishEvent(event)} calls, on the publisher's thread, the {@code @EventListener} methods
     * (also {@code @TransactionalEventListener}, after the commit) and {@code ApplicationListener}s that take the
     * event's static type or a supertype of it.
     */
    private Set<JavaSootMethod> listeners(ClassType eventType) {
        if (eventType.getFullyQualifiedName().equals("java.lang.Object")) {
            return Set.of();
        }
        Set<String> accepted = new HashSet<>(Set.of(eventType.getFullyQualifiedName()));
        context.superClassesOf(eventType).forEach(type -> accepted.add(type.getFullyQualifiedName()));
        context.interfacesOf(eventType).forEach(type -> accepted.add(type.getFullyQualifiedName()));
        accepted.remove("java.lang.Object");
        Set<JavaSootMethod> found = new LinkedHashSet<>();
        listeners().forEach((method, types) -> {
            if (types.stream().anyMatch(accepted::contains)) {
                found.add(method);
            }
        });
        return found;
    }

    private Map<JavaSootMethod, List<String>> listeners() {
        if (listeners == null) {
            listeners = new LinkedHashMap<>();
            for (JavaSootClass cls : context.applicationClasses()) {
                boolean applicationListener = context.interfacesOf(cls.getType()).stream()
                        .anyMatch(type -> type.getFullyQualifiedName().equals(APPLICATION_LISTENER));
                for (JavaSootMethod method : cls.getMethods()) {
                    if (!method.isConcrete()) {
                        continue;
                    }
                    Optional<AnnotationUsage> annotation = context.findAnnotation(method,
                            EVENT_LISTENER);
                    if (annotation.isPresent()) {
                        List<String> classes = new ArrayList<>(Annotations.strings(annotation.get(), "classes"));
                        classes.addAll(Annotations.strings(annotation.get(), "value"));
                        if (classes.isEmpty() && method.getParameterCount() > 0) {
                            classes.add(method.getParameterType(0).toString());
                        }
                        listeners.put(method, classes);
                    }
                    else if (applicationListener && method.getName().equals("onApplicationEvent")
                            && method.getParameterCount() == 1 && !MethodModifier.isBridge(method.getModifiers())) {
                        listeners.put(method, List.of(method.getParameterType(0).toString()));
                    }
                }
            }
        }
        return listeners;
    }

    private boolean isClosure(ClassType type, String closureClass) {
        return context.superClassesOf(type).stream()
                .anyMatch(superclass -> superclass.getFullyQualifiedName().equals(closureClass));
    }

    private void overrides(ClassType declared, MethodSubSignature subSignature, Set<JavaSootMethod> targets) {
        context.subtypesOf(declared)
                .forEach(subtype -> context.findClass(subtype)
                        .flatMap(cls -> cls.getMethod(subSignature))
                        .filter(JavaSootMethod::isConcrete)
                        .ifPresent(targets::add));
    }

    /**
     * The concrete method a call on {@code type} runs, looking up the superclass chain.
     */
    private Optional<JavaSootMethod> concreteImplementation(ClassType type, MethodSubSignature subSignature) {
        List<ClassType> chain = new ArrayList<>(List.of(type));
        chain.addAll(context.superClassesOf(type));
        for (ClassType candidate : chain) {
            if (!context.isApplication(candidate)) {
                break;
            }
            Optional<JavaSootMethod> method = context.findClass(candidate).flatMap(cls -> cls.getMethod(subSignature));
            if (method.isPresent()) {
                return method.filter(JavaSootMethod::isConcrete);
            }
        }
        return Optional.empty();
    }
}
