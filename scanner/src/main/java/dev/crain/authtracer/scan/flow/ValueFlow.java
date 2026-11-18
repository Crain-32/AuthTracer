package dev.crain.authtracer.scan.flow;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.Shape.Composite;
import dev.crain.authtracer.scan.flow.Shape.Function;
import dev.crain.authtracer.scan.flow.Shape.Leaf;
import dev.crain.authtracer.scan.flow.TypeProperties.Property;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.Constant;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractBinopExpr;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.AbstractUnopExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JInstanceOfExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JInstanceFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JThisRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JIfStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.jimple.javabytecode.stmt.JSwitchStmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * Field-level value flow: what each method returns, in terms of fields and its own parameters.
 * Fields are identified by type and property, so an accessor call on an application type is a read of that field.
 * Branch conditions ({@code if}s, and {@code switch} keys) count as flows into the returned value (an implicit flow),
 * so a value chosen by testing a field is computed from it. A gRPC handler returns what it passes to
 * {@code StreamObserver.onNext(..)}, and a protobuf message is built field by field through its builder (decision
 * 0032).
 */
@Supports(Feature.FIELD_LINEAGE)
public final class ValueFlow {

    /**
     * Library calls that pass their receiver or arguments through unchanged (collections, streams, optionals).
     */
    private static final Set<String> PRESERVING = Set.of("stream", "parallelStream", "toList", "collect", "filter",
            "sorted", "distinct", "limit", "skip", "peek", "get", "getFirst", "getLast", "orElse", "orElseThrow",
            "orElseGet", "iterator", "next", "of", "ofNullable", "copyOf", "asList", "singletonList", "singleton",
            "unmodifiableList", "unmodifiableSet", "unmodifiableCollection", "findFirst", "findAny", "values",
            "requireNonNull", "requireNonNullElse", "getBody", "ok", "body", "bodyValue",
            // Kotlin's coroutine extensions on ServerResponse.BodyBuilder (decision 0022).
            "bodyValueAndAwait", "bodyValueWithTypeAndAwait", "bodyAndAwait");
    /**
     * Library calls whose function argument tests, orders, observes or throws but doesn't become the result: a
     * predicate, comparator, consumer or exception supplier. The result is the receiver's elements.
     */
    private static final Set<String> KEEPING = Set.of("filter", "sorted", "sort", "min", "max", "peek", "ifPresent",
            "ifPresentOrElse", "takeWhile", "dropWhile", "orElseThrow", "forEach", "forEachOrdered", "removeIf",
            "doOnNext", "doOnSuccess", "doOnError", "doOnEach", "doOnComplete", "doFinally", "whenComplete",
            "filterWhen");
    /**
     * Library calls whose result is the receiver's value or, when it has none, the function's.
     */
    private static final Set<String> FALLING_BACK = Set.of("orElseGet", "or", "onErrorResume", "exceptionally",
            "computeIfAbsent");
    /**
     * Library calls that pick some of the receiver's elements by key, index or count, or wait for its value (a
     * Reactor pipeline's {@code block(timeout)}).
     */
    private static final Set<String> LOOKUPS = Set.of("get", "getOrDefault", "limit", "skip", "block",
            "blockOptional", "blockFirst", "blockLast");
    /**
     * Library factories of a comparator: it carries no data of its own.
     */
    private static final Set<String> COMPARING = Set.of("comparing", "comparingInt", "comparingLong",
            "comparingDouble", "thenComparing", "thenComparingInt", "thenComparingLong", "thenComparingDouble");
    /**
     * Library mutators that store a value in their receiver: the value is the last argument, but {@code merge}'s
     * (its second; the last is the function).
     */
    private static final Set<String> COLLECTING = Set.of("add", "addAll", "put", "putAll", "offer", "push", "set",
            "addFirst", "addLast", "offerFirst", "offerLast", "putFirst", "putLast", "putIfAbsent", "replace",
            "merge");
    /**
     * Text built a call at a time: what the receiver holds afterwards is computed from what was added.
     */
    private static final Set<String> TEXT_BUILDERS = Set.of("java.lang.StringBuilder", "java.lang.StringBuffer",
            "java.lang.AbstractStringBuilder", "java.util.StringJoiner");
    private static final Set<String> APPENDING = Set.of("append", "appendCodePoint", "insert", "replace", "add",
            "setCharAt", "merge");
    /**
     * Library types that describe code, not data: what a library call returns of them holds no field's value.
     */
    private static final Set<String> METADATA = Set.of("java.lang.Class", "java.lang.reflect.Method");
    private static final String STRING_CONCAT = "java.lang.invoke.StringConcatFactory";
    private static final int MAX_BUILDER_CHAIN = 64;
    private static final int MAX_RECURSION_PASSES = 4;
    private static final String STREAM_OBSERVER = "io.grpc.stub.StreamObserver";
    private static final String CONTINUATION = "kotlin.coroutines.Continuation";
    private static final String SCRIPT_BYTECODE_ADAPTER = "org.codehaus.groovy.runtime.ScriptBytecodeAdapter";

    /**
     * The parameter a builder method's {@code this} stands for in its summary; its field reads are
     * {@link #receiverField}.
     */
    private static final int RECEIVER = -1;

    /**
     * @param receiverFields the fields of {@code this} a builder method reads before it sets them, in the order
     *        their {@link #receiverField} parameters number them
     */
    private record Summary(Shape returned, Map<String, Shape> thisFields, List<String> receiverFields) {
        static final Summary EMPTY = new Summary(Shape.EMPTY, Map.of(), List.of());
    }

    /**
     * The parameter a builder method's read of the {@code i}th receiver field stands for.
     */
    private static int receiverField(int i) {
        return -2 - i;
    }

    private final ScanContext context;
    private final TypeProperties properties;
    private final CallTraversal resolver;
    private final Map<String, Summary> summaries = new ConcurrentHashMap<>();
    private final Map<Applied, Shape> applied = new ConcurrentHashMap<>();
    private final Set<String> inProgress = new HashSet<>();
    /**
     * The methods being summarised, innermost last; those a recursive call came back to, with what they return so
     * far; and those whose summary used such an unfinished one, which isn't kept.
     */
    private final Deque<String> summarising = new ArrayDeque<>();
    private final Map<String, Summary> provisional = new HashMap<>();
    private final Set<String> unfinished = new HashSet<>();

    public ValueFlow(ScanContext context, TypeProperties properties, CallTraversal resolver) {
        this.context = context;
        this.properties = properties;
        this.resolver = resolver;
    }

    public Shape returnShape(JavaSootMethod method) {
        return summary(method).returned();
    }

    /**
     * Whether what the method returns depends on its parameter, e.g. a denial handler's on the result it was given.
     */
    @Supports(Feature.FIELD_CHECKS)
    public boolean derivesFrom(JavaSootMethod method, int parameter) {
        Set<Integer> params = new LinkedHashSet<>();
        Shape.collect(returnShape(method), new LinkedHashSet<>(), params);
        return params.contains(parameter);
    }

    /**
     * Where a value a method passes on comes from, e.g. the payload it sends to a message topic: its shape once the
     * whole method has run (reassigned locals merge).
     */
    public Shape argumentShape(JavaSootMethod method, Value argument) {
        Analysis analysis = new Analysis(method);
        analysis.run();
        return analysis.eval(argument);
    }

    /**
     * The same, the method read with the arguments one call gives it: a value whose fields are known (a DTO a client
     * maps a reply into) is read as code reads it on a local, as {@link #returnedWith} reads a function, so the
     * lineage goes on to where its fields came from.
     */
    public Shape argumentShape(JavaSootMethod method, Value argument, List<Shape> args) {
        Analysis analysis = new Analysis(method, args);
        analysis.run();
        return analysis.eval(argument);
    }

    /**
     * The shapes of a call's arguments, where the caller makes it.
     */
    public List<Shape> argumentsAt(JavaSootMethod caller, AbstractInvokeExpr call) {
        Analysis analysis = new Analysis(caller);
        analysis.run();
        return call.getArgs().stream().map(analysis::eval).toList();
    }

    /**
     * A shape in terms of a method's parameters, in terms of what a caller passes it instead: the shapes of the
     * call's arguments where the caller makes it.
     */
    public Shape atCallSite(Shape shape, JavaSootMethod caller, AbstractInvokeExpr call) {
        Analysis analysis = new Analysis(caller);
        analysis.run();
        return substitute(shape, call.getArgs().stream().map(analysis::eval).toList());
    }

    /**
     * Decision 0098: a shape in terms of a lambda's (or method reference's) parameters, in terms of the method that
     * creates it: what it captures where it is created, then what it is handed, the elements of the call it is
     * passed to ({@code orders.forEach(order -> ..)}'s {@code orders}), or nothing known for any other call.
     *
     * @param lambda the lambda's body, or the method referenced
     * @param creation the statement that creates it
     */
    public Shape atLambda(Shape shape, JavaSootMethod lambda, JavaSootMethod creator, Stmt creation,
            JDynamicInvokeExpr created) {
        Analysis analysis = new Analysis(creator);
        analysis.run();
        // An instance lambda's (a bound reference's) first capture is its receiver, not a parameter.
        int receiver = lambda.isStatic() ? 0 : Math.min(1, created.getArgCount());
        List<Shape> captured = created.getArgs().subList(receiver, created.getArgCount()).stream()
                .map(analysis::eval).toList();
        Local function = (Local) ((AbstractDefinitionStmt) creation).getLeftOp();
        Shape elements = creator.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(call -> call.getArgs().contains(function)).findFirst()
                .filter(AbstractInstanceInvokeExpr.class::isInstance)
                .map(call -> analysis.eval(((AbstractInstanceInvokeExpr) call).getBase())).orElse(Shape.EMPTY);
        List<Shape> args = new ArrayList<>(captured);
        args.addAll(Collections.nCopies(Math.max(0, lambda.getParameterCount() - captured.size()), elements));
        return substitute(shape, args);
    }

    private Summary summary(JavaSootMethod method) {
        // The full signature: a bridge (Object run()) and the method it bridges (Account run()) differ only in what
        // they return, and the bridge's summary is not the real method's.
        String key = method.getSignature().toString();
        Summary cached = summaries.get(key);
        if (cached != null) {
            return cached;
        }
        if (!method.hasBody()) {
            return Summary.EMPTY;
        }
        if (summarising.contains(key)) {
            // Recursion (a tree mapper, A -> B -> A): what the method returns so far. The methods between used it,
            // so their summaries aren't kept; the method itself is read again until what it returns settles.
            provisional.putIfAbsent(key, Summary.EMPTY);
            boolean inner = false;
            for (String entered : summarising) {
                if (inner) {
                    unfinished.add(entered);
                }
                inner = inner || entered.equals(key);
            }
            return provisional.get(key);
        }
        if (!inProgress.add(key)) {
            return Summary.EMPTY;
        }
        summarising.addLast(key);
        try {
            Summary summary = new Analysis(method).run();
            for (int pass = 0; provisional.containsKey(key) && pass < MAX_RECURSION_PASSES; pass++) {
                provisional.put(key, summary);
                Summary again = new Analysis(method).run();
                if (again.equals(summary)) {
                    break;
                }
                summary = again;
            }
            provisional.remove(key);
            if (!unfinished.remove(key)) {
                summaries.put(key, summary);
            }
            return summary;
        }
        finally {
            summarising.removeLast();
            inProgress.remove(key);
        }
    }

    /**
     * One pass over a method body in statement order; reassigned locals accumulate (merge) rather than overwrite.
     */
    private final class Analysis {

        private final JavaSootMethod method;
        private final Local thisLocal;
        private final Map<Local, Shape> locals = new HashMap<>();
        private final Map<Local, String> pendingNew = new HashMap<>();
        private final Map<String, Shape> thisFields = new LinkedHashMap<>();
        private final List<Shape> conditions = new ArrayList<>();
        private final List<String> receiverFields = new ArrayList<>();
        /**
         * A fluent builder's method ({@code OrderDto$OrderDtoBuilder.name(..)}, Lombok's or one written by hand):
         * {@code this} and its fields stand for the receiver at the call, so a chain of them carries what each set.
         */
        private final boolean builder;
        /**
         * What the parameters hold at one call, for a constructor read with its arguments; {@code null} for the
         * method's own summary, whose parameters stand for any.
         */
        private final List<Shape> arguments;
        private Shape returned;

        Analysis(JavaSootMethod method) {
            this(method, null);
        }

        Analysis(JavaSootMethod method, List<Shape> arguments) {
            this.method = method;
            this.arguments = arguments;
            this.thisLocal = method.isStatic() ? null : method.getBody().getThisLocal();
            String declaring = method.getDeclaringClassType().getFullyQualifiedName();
            // A protobuf message's builder is read as one (protobufBuilder), not through its generated code.
            this.builder = thisLocal != null && declaring.substring(Math.max(declaring.lastIndexOf('.'),
                    declaring.lastIndexOf('$')) + 1).endsWith("Builder") && !(declaring.endsWith("$Builder")
                            && properties.isProtobufMessage(declaring.substring(0, declaring.length() - 8)));
        }

        Summary run() {
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition) {
                    assign(definition);
                }
                else if (stmt instanceof JIfStmt branch) {
                    conditions.add(Shape.computed(branch.getCondition().getUses().stream().map(this::eval).toList()));
                }
                else if (stmt instanceof JSwitchStmt choice) {
                    conditions.add(Shape.computed(List.of(eval(choice.getKey()))));
                }
                else if (stmt instanceof JReturnStmt result) {
                    returned = Shape.merge(returned, eval(result.getOp()));
                }
                else if (stmt.isInvokableStmt()) {
                    stmt.asInvokableStmt().getInvokeExpr().ifPresent(this::invokeStatement);
                }
            }
            Shape result = returned == null ? Shape.EMPTY : returned;
            Leaf implicit = Shape.computed(conditions);
            if (result instanceof Leaf leaf && !implicit.isEmpty()) {
                result = Shape.union(leaf, implicit, true);
            }
            return new Summary(result, thisFields, List.copyOf(receiverFields));
        }

        private void assign(AbstractDefinitionStmt definition) {
            Value right = definition.getRightOp();
            if (definition.getLeftOp() instanceof Local local) {
                if (right instanceof JParameterRef parameter) {
                    locals.put(local, arguments == null ? Leaf.param(parameter.getIndex())
                            : parameter.getIndex() < arguments.size() ? arguments.get(parameter.getIndex())
                                    : Shape.EMPTY);
                }
                else if (right instanceof JThisRef && builder) {
                    locals.put(local, Leaf.param(RECEIVER));
                }
                else if (right instanceof JNewExpr created) {
                    pendingNew.put(local, created.getType().getFullyQualifiedName());
                    locals.put(local, Shape.EMPTY);
                }
                else {
                    locals.merge(local, eval(right), Shape::merge);
                    if (right instanceof AbstractInvokeExpr invoke) {
                        appended(invoke, locals.get(local));
                    }
                }
            }
            else if (definition.getLeftOp() instanceof JInstanceFieldRef field && field.getBase().equals(thisLocal)) {
                thisFields.merge(field.getFieldSignature().getName(), eval(right), Shape::merge);
            }
            else if (definition.getLeftOp() instanceof JInstanceFieldRef field
                    && locals.get(field.getBase()) instanceof Composite composite
                    && properties.byName(composite.type(), field.getFieldSignature().getName()).isPresent()) {
                // A public field of an object built here: the property now holds the value.
                Map<String, Shape> components = new LinkedHashMap<>(composite.components());
                components.put(field.getFieldSignature().getName(), eval(right));
                locals.put(field.getBase(), new Composite(composite.type(), components));
            }
            else if (definition.getLeftOp() instanceof JArrayRef array) {
                locals.merge(array.getBase(), eval(right), Shape::merge);
            }
        }

        private void invokeStatement(AbstractInvokeExpr invoke) {
            if (invoke.getMethodSignature().getName().equals("onNext") && invoke.getArgCount() == 1
                    && invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(STREAM_OBSERVER)) {
                // A gRPC handler answers through its StreamObserver.
                returned = Shape.merge(returned, eval(invoke.getArg(0)));
                return;
            }
            if (invoke instanceof AbstractInstanceInvokeExpr instance
                    && invoke.getMethodSignature().getName().equals("<init>")
                    && pendingNew.containsKey(instance.getBase())) {
                locals.put(instance.getBase(), construct(pendingNew.remove(instance.getBase()), invoke));
                return;
            }
            if (invoke instanceof AbstractInstanceInvokeExpr instance && invoke.getArgCount() == 1
                    && locals.get(instance.getBase()) instanceof Composite composite) {
                Optional<String> property = setProperty(composite, invoke.getMethodSignature().getName());
                if (property.isPresent()) {
                    // A setter on an object built here (a JavaBean, or a statically compiled Groovy object built
                    // with named arguments): the property now holds the argument.
                    Map<String, Shape> components = new LinkedHashMap<>(composite.components());
                    components.put(property.get(), eval(invoke.getArg(0)));
                    locals.put(instance.getBase(), new Composite(composite.type(), components));
                    return;
                }
            }
            String name = invoke.getMethodSignature().getName();
            if (invoke instanceof AbstractInstanceInvokeExpr instance
                    && !context.isApplication(invoke.getMethodSignature().getDeclClassType())
                    && COLLECTING.contains(name)) {
                // The value is the last argument: put(key, value) and set(index, value) don't store the key.
                int value = name.equals("merge") ? 1 : invoke.getArgCount() - 1;
                if (value >= 0 && value < invoke.getArgCount()) {
                    locals.merge(instance.getBase(), eval(invoke.getArg(value)), Shape::merge);
                }
                return;
            }
            if (invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals("java.util.Collections")
                    && name.equals("addAll") && invoke.getArgCount() == 2 && invoke.getArg(0) instanceof Local into) {
                // Collections.addAll(list, a, b): the varargs array's elements go into the list.
                locals.merge(into, eval(invoke.getArg(1)), Shape::merge);
                return;
            }
            if (!appended(invoke, null)) {
                call(invoke);
            }
        }

        /**
         * Text built a statement at a time ({@code sb.append(ssn); sb.append(name); dto.setLabel(sb.toString())}):
         * the builder, and each local that is the same builder ({@code append} returns it), holds what was added.
         *
         * @param result what the call returned, when that was assigned; else it is evaluated here
         * @return whether the call was one
         */
        private boolean appended(AbstractInvokeExpr invoke, Shape result) {
            if (!(invoke instanceof AbstractInstanceInvokeExpr instance) || invoke.getArgCount() == 0
                    || !APPENDING.contains(invoke.getMethodSignature().getName())
                    || !(instance.getBase() instanceof Local base) || !TEXT_BUILDERS.contains(
                            invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName())) {
                return false;
            }
            Shape added = result != null ? result : call(invoke);
            Local same = base;
            for (int i = 0; same != null && i < MAX_BUILDER_CHAIN; i++) {
                locals.merge(same, added, Shape::merge);
                same = Locals.definition(method.getBody(), same)
                        .filter(definition -> definition instanceof AbstractInstanceInvokeExpr call
                                && TEXT_BUILDERS.contains(call.getMethodSignature().getDeclClassType()
                                        .getFullyQualifiedName()))
                        .map(definition -> ((AbstractInstanceInvokeExpr) definition).getBase())
                        .filter(Local.class::isInstance).map(Local.class::cast).orElse(null);
            }
            return true;
        }

        private Optional<String> setProperty(Composite composite, String setter) {
            if (setter.length() < 4 || !setter.startsWith("set")) {
                return Optional.empty();
            }
            String name = Character.toLowerCase(setter.charAt(3)) + setter.substring(4);
            return properties.byName(composite.type(), name).map(Property::name);
        }

        private Shape eval(Value value) {
            if (value instanceof Local local) {
                return locals.getOrDefault(local, Shape.EMPTY);
            }
            if (value instanceof Constant) {
                return Shape.EMPTY;
            }
            if (value instanceof JCastExpr cast) {
                return eval(cast.getOp());
            }
            if (value instanceof AbstractBinopExpr binop) {
                return Shape.computed(List.of(eval(binop.getOp1()), eval(binop.getOp2())));
            }
            if (value instanceof AbstractUnopExpr unop) {
                return Shape.computed(List.of(eval(unop.getOp())));
            }
            if (value instanceof JInstanceOfExpr instanceOf) {
                return Shape.computed(List.of(eval(instanceOf.getOp())));
            }
            if (value instanceof JArrayRef array) {
                return eval(array.getBase());
            }
            if (value instanceof JInstanceFieldRef field) {
                return fieldRead(field);
            }
            if (value instanceof JDynamicInvokeExpr dynamic) {
                return dynamic(dynamic);
            }
            if (value instanceof AbstractInvokeExpr invoke) {
                return call(invoke);
            }
            return Shape.EMPTY;
        }

        private Shape fieldRead(JInstanceFieldRef field) {
            if (field.getBase().equals(thisLocal)) {
                if (!builder) {
                    return Shape.EMPTY;
                }
                String name = field.getFieldSignature().getName();
                if (thisFields.containsKey(name)) {
                    return thisFields.get(name);
                }
                if (!receiverFields.contains(name)) {
                    receiverFields.add(name);
                }
                return Leaf.param(receiverField(receiverFields.indexOf(name)));
            }
            String owner = field.getFieldSignature().getDeclClassType().getFullyQualifiedName();
            String name = field.getFieldSignature().getName();
            if (eval(field.getBase()) instanceof Composite composite && composite.components().containsKey(name)) {
                return composite.components().get(name);
            }
            return properties.byName(owner, name).map(p -> (Shape) Leaf.field(Field.id(owner, p.name())))
                    .orElse(Shape.EMPTY);
        }

        private Shape dynamic(JDynamicInvokeExpr dynamic) {
            String bootstrap = dynamic.getBootstrapMethodSignature().getDeclClassType().getFullyQualifiedName();
            if (bootstrap.equals(STRING_CONCAT)) {
                return Shape.computed(dynamic.getArgs().stream().map(this::eval).toList());
            }
            for (Value argument : dynamic.getBootstrapArgs()) {
                if (argument instanceof MethodHandle handle
                        && handle.getReferenceSignature() instanceof MethodSignature target
                        && context.isApplication(target.getDeclClassType())) {
                    return new Function(target, dynamic.getArgs().stream().map(this::eval).toList());
                }
            }
            return Shape.EMPTY;
        }

        private Shape call(AbstractInvokeExpr invoke) {
            MethodSignature signature = invoke.getMethodSignature();
            String owner = signature.getDeclClassType().getFullyQualifiedName();
            Shape receiver = invoke instanceof AbstractInstanceInvokeExpr instance ? eval(instance.getBase()) : null;
            List<Shape> args = invoke.getArgs().stream().map(this::eval).toList();

            Optional<Shape> accessed = receiver == null ? Optional.empty()
                    : accessor(owner, signature.getName(), signature.getParameterCount(), receiver);
            if (accessed.isPresent()) {
                return accessed.get();
            }
            Optional<Shape> built = protobufBuilder(owner, signature.getName(), receiver, args);
            if (built.isPresent()) {
                return built.get();
            }
            if (context.isApplication(signature.getDeclClassType())) {
                Shape result = null;
                for (JavaSootMethod target : resolver.targets(invoke)) {
                    Summary summary = summary(target);
                    if (summary.receiverFields().isEmpty() && !builderSummary(summary)) {
                        result = Shape.merge(result, substitute(summary.returned(), args));
                        continue;
                    }
                    // A builder method: the receiver with the fields it sets, its reads the receiver's fields.
                    Shape before = receiver == null ? Shape.EMPTY : receiver;
                    Map<String, Shape> fields = new LinkedHashMap<>(before instanceof Composite composite
                            ? composite.components() : Map.of());
                    summary.thisFields().forEach((field, shape) -> fields.put(field, substitute(shape, args)));
                    Shape after = new Composite(target.getDeclaringClassType().getFullyQualifiedName(), fields);
                    if (invoke instanceof AbstractInstanceInvokeExpr instance && !summary.thisFields().isEmpty()) {
                        locals.put(instance.getBase(), after);
                    }
                    result = Shape.merge(result, substitute(summary.returned(), index -> {
                        if (index == RECEIVER) {
                            return after;
                        }
                        if (index < RECEIVER) {
                            String field = summary.receiverFields().get(-2 - index);
                            return before instanceof Composite composite
                                    ? composite.components().getOrDefault(field, Shape.EMPTY) : Shape.EMPTY;
                        }
                        return index < args.size() ? args.get(index) : Shape.EMPTY;
                    }));
                }
                return result == null ? Shape.EMPTY : result;
            }
            if (signature.getType() instanceof ClassType returned
                    && METADATA.contains(returned.getFullyQualifiedName())) {
                // An invocation's Method or a value's class carries no field's value.
                return Shape.EMPTY;
            }
            String name = signature.getName();
            if (owner.equals(SCRIPT_BYTECODE_ADAPTER) && name.equals("createMap") && invoke.getArgCount() == 1
                    && invoke.getArg(0) instanceof Local array) {
                Optional<Shape> named = namedArguments(array);
                if (named.isPresent()) {
                    return named.get();
                }
            }
            Optional<Map<String, Shape>> entries = receiver == null ? Optional.empty() : Shape.entries(receiver);
            if (entries.isPresent() && List.of("get", "getOrDefault").contains(name)
                    && invoke.getArg(0) instanceof StringConstant key) {
                // A named argument looked up by its name.
                Shape value = entries.get().getOrDefault(key.getValue(), Shape.EMPTY);
                return name.equals("getOrDefault") && args.size() == 2 ? Shape.merge(value, args.get(1)) : value;
            }
            if (entries.isPresent()) {
                receiver = Shape.values(receiver);
            }
            if (receiver != null && KEEPING.contains(name)) {
                return receiver;
            }
            if (receiver != null && List.of("anyMatch", "allMatch", "noneMatch").contains(name)) {
                return Shape.computed(List.of(receiver));
            }
            if (COMPARING.contains(name)) {
                return Shape.EMPTY;
            }
            for (Shape arg : args) {
                List<Function> functions = Shape.functions(arg);
                if (functions.isEmpty()) {
                    continue;
                }
                // orElseGet(() -> ..): the receiver's value, or the supplier's. A function chosen on branches is
                // any of them.
                Shape result = FALLING_BACK.contains(name) ? receiver : null;
                for (Function function : functions) {
                    result = Shape.merge(result, apply(function, FALLING_BACK.contains(name) ? null : receiver));
                }
                return result;
            }
            if (receiver != null && LOOKUPS.contains(name)) {
                // get(key), limit(n): the receiver's elements; the key says which, it isn't copied.
                return name.equals("getOrDefault") && args.size() == 2 ? Shape.merge(receiver, args.get(1))
                        : receiver;
            }
            if (PRESERVING.contains(name)) {
                Shape result = receiver;
                for (int i = 0; i < args.size(); i++) {
                    // A suspend call's Continuation carries no data.
                    if (!(signature.getParameterTypes().get(i) instanceof ClassType type
                            && type.getFullyQualifiedName().equals(CONTINUATION))) {
                        result = Shape.merge(result, args.get(i));
                    }
                }
                return result == null ? Shape.EMPTY : result;
            }
            List<Shape> inputs = new ArrayList<>();
            if (receiver != null) {
                inputs.add(receiver);
            }
            inputs.addAll(args);
            return Shape.computed(inputs);
        }

        /**
         * Groovy's map of named arguments, {@code [name: n, taxId: t]}, which it builds as
         * {@code createMap(["name", n, "taxId", t])}: the values by their constant keys.
         */
        private Optional<Shape> namedArguments(Local array) {
            Map<Integer, Value> elements = new HashMap<>();
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JArrayRef
                        element && element.getBase().equals(array) && element.getIndex() instanceof IntConstant index) {
                    elements.put(index.getValue(), definition.getRightOp());
                }
            }
            Map<String, Shape> entries = new LinkedHashMap<>();
            for (int i = 0; i < elements.size(); i += 2) {
                if (!(elements.get(i) instanceof StringConstant key) || !elements.containsKey(i + 1)) {
                    return Optional.empty();
                }
                entries.put(key.getValue(), eval(elements.get(i + 1)));
            }
            return Optional.of(new Composite(Shape.MAP, entries));
        }

        /**
         * A protobuf message's builder: {@code Msg.newBuilder()} starts an empty message, {@code setX(v)} fills a
         * field and returns the builder, {@code build()} returns the message.
         */
        private Optional<Shape> protobufBuilder(String owner, String name, Shape receiver, List<Shape> args) {
            if (receiver == null) {
                return name.equals("newBuilder") && args.isEmpty() && properties.isProtobufMessage(owner)
                        ? Optional.of(new Composite(owner, Map.of())) : Optional.empty();
            }
            if (!owner.endsWith("$Builder") || !(receiver instanceof Composite composite)
                    || !composite.type().equals(owner.substring(0, owner.length() - "$Builder".length()))) {
                return Optional.empty();
            }
            if (name.equals("build") || name.equals("buildPartial")) {
                return Optional.of(composite);
            }
            Optional<String> property = args.size() == 1 ? setProperty(composite, name) : Optional.empty();
            Map<String, Shape> components = new LinkedHashMap<>(composite.components());
            if (property.isPresent()) {
                components.put(property.get(), args.getFirst());
                return Optional.of(new Composite(composite.type(), components));
            }
            // addX(v), addAllX(vs), putX(k, v), putAllX(m), setX(i, v): the repeated or map field x holds v too.
            for (String prefix : List.of("addAll", "putAll", "add", "put", "set")) {
                String rest = name.startsWith(prefix) ? name.substring(prefix.length()) : "";
                Optional<String> filled = rest.isEmpty() || !Character.isUpperCase(rest.charAt(0)) || args.isEmpty()
                        ? Optional.empty() : properties.byName(composite.type(),
                                Character.toLowerCase(rest.charAt(0)) + rest.substring(1)).map(Property::name);
                if (filled.isPresent()) {
                    components.merge(filled.get(), args.getLast(), Shape::merge);
                    return Optional.of(new Composite(composite.type(), components));
                }
            }
            return Optional.of(composite);
        }

        /**
         * {@code stream.map(Mapper::from)} and friends: the function's result, applied to the elements.
         */
        private Shape apply(Function function, Shape elements) {
            Optional<JavaSootMethod> target = context.findMethod(function.target());
            if (target.isEmpty()) {
                return Shape.EMPTY;
            }
            MethodSignature signature = function.target();
            Optional<Shape> accessed = target.get().isStatic() ? Optional.empty()
                    : accessor(signature.getDeclClassType().getFullyQualifiedName(), signature.getName(),
                            signature.getParameterCount(), elements == null ? Shape.EMPTY : elements);
            if (accessed.isPresent()) {
                return accessed.get();
            }
            // Captured values come first, then the element; an instance target's first capture is its receiver.
            List<Shape> args = new ArrayList<>(function.captured());
            if (!target.get().isStatic() && !args.isEmpty()) {
                args.removeFirst();
            }
            args.add(elements == null ? Shape.EMPTY : elements);
            if (args.stream().anyMatch(arg -> arg instanceof Composite composite && Shape.entries(arg).isEmpty()
                    && properties.isApplicationType(composite.type()))) {
                // Values whose fields are known, e.g. a DTO a client maps a gRPC reply into: the function reads them
                // as code reads them on a local, so the lineage goes on to where they came from.
                return returnedWith(target.get(), args);
            }
            return substitute(summary(target.get()).returned(), args);
        }

        /**
         * A record accessor or getter call on an application type: a read of that field.
         */
        private Optional<Shape> accessor(String owner, String name, int parameterCount, Shape receiver) {
            if (parameterCount != 0 || !properties.isApplicationType(owner)) {
                return Optional.empty();
            }
            return properties.byAccessor(owner, name).map(property -> {
                if (receiver instanceof Composite composite && composite.type().equals(owner)) {
                    Shape component = composite.components().get(property.name());
                    // A known component built from other fields carries their origins; one built from constants
                    // has none, so the property itself is where the value comes from.
                    if (component != null && !(component instanceof Leaf leaf && leaf.isEmpty())) {
                        return component;
                    }
                }
                return Leaf.field(Field.id(owner, property.name()));
            });
        }

        private Shape construct(String type, AbstractInvokeExpr constructor) {
            List<Shape> args = constructor.getArgs().stream().map(this::eval).toList();
            if (!properties.isApplicationType(type)) {
                if (args.size() == 1 && args.getFirst() instanceof Composite) {
                    return args.getFirst();
                }
                return Shape.computed(args);
            }
            Map<String, Shape> components = new LinkedHashMap<>();
            List<Property> declared = properties.of(type);
            if (context.classFiles().isRecord(type) && declared.size() == args.size()) {
                for (int i = 0; i < args.size(); i++) {
                    components.put(declared.get(i).name(), args.get(i));
                }
            }
            else {
                context.findMethod(constructor.getMethodSignature()).ifPresent(ctor -> {
                    if (args.stream().anyMatch(arg -> Shape.entries(arg).isPresent())) {
                        // Given named arguments: read with them, so each field gets the one of its name.
                        components.putAll(withArguments(ctor, args));
                    }
                    else {
                        summary(ctor).thisFields().forEach((field, shape) -> components.put(field,
                                substitute(shape, args)));
                    }
                });
            }
            return new Composite(type, components);
        }
    }

    /**
     * The fields a constructor sets, read with the arguments of one call.
     */
    private Map<String, Shape> withArguments(JavaSootMethod constructor, List<Shape> args) {
        String key = constructor.getSignature() + " with arguments";
        if (!constructor.hasBody() || !inProgress.add(key)) {
            return Map.of();
        }
        try {
            return new Analysis(constructor, args).run().thisFields();
        }
        finally {
            inProgress.remove(key);
        }
    }

    /**
     * What a function returns when applied to these values: read with them, as {@link #withArguments} reads a
     * constructor.
     */
    private Shape returnedWith(JavaSootMethod function, List<Shape> args) {
        Applied key = new Applied(function.getSignature().toString(), List.copyOf(args));
        Shape cached = applied.get(key);
        if (cached != null) {
            return cached;
        }
        if (!function.hasBody() || !inProgress.add(key.toString())) {
            return substitute(summary(function).returned(), args);
        }
        try {
            Shape returned = new Analysis(function, args).run().returned();
            applied.put(key, returned);
            return returned;
        }
        finally {
            inProgress.remove(key.toString());
        }
    }

    private record Applied(String function, List<Shape> args) {
    }

    /**
     * A summary that stands for its receiver: a builder method's returns {@code this}.
     */
    private static boolean builderSummary(Summary summary) {
        return summary.returned() instanceof Leaf leaf && leaf.params().contains(RECEIVER)
                || summary.returned() instanceof Composite composite && composite.components().values().stream()
                        .anyMatch(component -> component instanceof Leaf leaf && leaf.params().stream()
                                .anyMatch(index -> index < 0));
    }

    /**
     * Replaces a callee's parameter references with the caller's argument shapes.
     */
    static Shape substitute(Shape shape, List<Shape> args) {
        return substitute(shape, index -> index >= 0 && index < args.size() ? args.get(index) : Shape.EMPTY);
    }

    private static Shape substitute(Shape shape, java.util.function.IntFunction<Shape> args) {
        if (shape instanceof Composite composite) {
            Map<String, Shape> components = new LinkedHashMap<>();
            composite.components().forEach((name, component) -> components.put(name, substitute(component, args)));
            return new Composite(composite.type(), components);
        }
        if (!(shape instanceof Leaf leaf) || leaf.params().isEmpty()) {
            return shape;
        }
        if (leaf.fields().isEmpty() && leaf.params().size() == 1 && !leaf.computed()) {
            return args.apply(leaf.params().iterator().next());
        }
        Set<String> fields = new LinkedHashSet<>(leaf.fields());
        Set<Integer> params = new LinkedHashSet<>();
        boolean computed = leaf.computed();
        for (int index : leaf.params()) {
            Shape arg = args.apply(index);
            if (arg != Shape.EMPTY) {
                Shape.collect(arg, fields, params);
                computed |= !(arg instanceof Leaf argLeaf) || argLeaf.computed();
            }
        }
        return new Leaf(fields, params, computed);
    }
}
