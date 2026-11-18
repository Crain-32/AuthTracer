package dev.crain.authtracer.scan;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.jspecify.annotations.NonNull;
import sootup.core.graph.MutableControlFlowGraph;
import sootup.core.interceptor.BodyInterceptor;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JInterfaceInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.expr.JVirtualInvokeExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JThisRef;
import sootup.core.jimple.common.stmt.FallsThroughStmt;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.Body;
import sootup.core.model.MethodModifier;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;
import sootup.core.types.NullType;
import sootup.core.types.PrimitiveType;
import sootup.core.types.Type;
import sootup.core.views.View;

/**
 * Types dynamic Groovy call chains (decision 0022, follow-up): outside {@code @CompileStatic} every call is an
 * invokedynamic that returns {@code Object}, so {@code client.post().uri(..).retrieve()} is untyped past the first
 * call. This interceptor follows the types the bytecode does know (parameters, fields, casts, {@code new}, the
 * call site's own receiver type) and, where a call's receiver type is known and its method resolves, replaces the
 * dynamic call with the ordinary invoke Groovy will make; the result has that method's return type, so the next call
 * in the chain resolves too. Everything downstream (egress, lineage, call paths) then reads Groovy like Java.
 * <ul>
 * <li>{@code invoke} calls, on an instance or a class (static), by name and number of arguments; among overloads,
 * the one whose parameter types the call site's match, else any when they all return the same type;</li>
 * <li>{@code getProperty} reads become the getter ({@code getX()}, {@code isX()}, a record's {@code x()}).</li>
 * </ul>
 * Calls that pass a closure stay dynamic: the Security DSL readers interpret those (decision 0022), except on
 * Spring's HTTP clients ({@link #CLOSURE_COERCING}), where the closure is the functional interface the method takes.
 * So do calls on Groovy's own types, whose dispatch the metaclass decides.
 */
@Supports({Feature.SERVICE_CALLS, Feature.FIELD_LINEAGE, Feature.CALL_PATHS})
public final class GroovyTypedCalls implements BodyInterceptor {

    private static final String OBJECT = "java.lang.Object";
    private static final String CLOSURE = "groovy.lang.Closure";
    /**
     * The packages of Spring's HTTP clients: calls on them that pass a closure are typed too, the closure coerced to
     * the functional interface the method takes ({@code uri { it.path('/x').build() }}). They are no DSL a reader
     * interprets.
     */
    private static final List<String> CLOSURE_COERCING = List.of("org.springframework.web.client.",
            "org.springframework.web.reactive.function.client.");
    private static final int MAX_SUPERTYPES = 64;
    private static final String SCRIPT_BYTECODE_ADAPTER = "org.codehaus.groovy.runtime.ScriptBytecodeAdapter";
    private static final Set<String> PROPERTY_SETTERS = Set.of("setGroovyObjectProperty", "setProperty");
    private static final String MAP = "java.util.Map";
    /**
     * Map types, and those a constructor can take Groovy's named-argument map (a LinkedHashMap) as.
     */
    private static final Set<String> MAPS = Set.of(MAP, "java.util.AbstractMap", "java.util.HashMap",
            "java.util.LinkedHashMap");

    @Override
    public void interceptBody(Body.@NonNull BodyBuilder builder, @NonNull View view) {
        MutableControlFlowGraph graph = builder.getControlFlowGraph();
        Map<Local, ClassType> types = new HashMap<>();
        // Array elements set by constant index, and the maps createMap(..) builds from them (named arguments).
        Map<Local, Map<Integer, Immediate>> arrays = new HashMap<>();
        Map<Local, Map<String, Immediate>> maps = new HashMap<>();
        for (Stmt stmt : builder.getStmts()) {
            if (stmt instanceof JIdentityStmt identity) {
                if (identity.getRightOp() instanceof JParameterRef parameter) {
                    classType(parameter.getType()).ifPresent(type -> types.put(identity.getLeftOp(), type));
                }
                else if (identity.getRightOp() instanceof JThisRef self && self.getType() instanceof ClassType cls) {
                    types.put(identity.getLeftOp(), cls);
                }
                continue;
            }
            if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof JArrayRef element
                    && element.getIndex() instanceof IntConstant index) {
                arrays.computeIfAbsent(element.getBase(), array -> new HashMap<>())
                        .put(index.getValue(), (Immediate) assign.getRightOp());
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            Optional<SootMethod> setter = invoke.flatMap(found -> setter(view, found, types));
            if (setter.isPresent()) {
                // view.label = value: Groovy runs the setter, as @CompileStatic compiles the assignment.
                graph.replaceNode(stmt, new JInvokeStmt(new JVirtualInvokeExpr((Local) invoke.get().getArg(2),
                        setter.get().getSignature(), List.of(invoke.get().getArg(0))), stmt.getPositionInfo()));
                continue;
            }
            Optional<GroovyCalls.Call> call = invoke.flatMap(GroovyCalls::of);
            if (stmt instanceof JAssignStmt assign && call.isPresent() && call.get().type().equals("getProperty")
                    && call.get().args().isEmpty() && call.get().receiver() instanceof Local map
                    && Optional.ofNullable(types.get(map)).filter(type -> MAPS.contains(type.getFullyQualifiedName()))
                            .isPresent()) {
                // args.holder on a Map is the entry Groovy looks up: args.get("holder").
                graph.replaceNode(stmt, assign.withRValue(mapGet(view, map, call.get().name())));
                continue;
            }
            if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof Local result) {
                if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("createMap")
                        && invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                .equals(SCRIPT_BYTECODE_ADAPTER)
                        && invoke.get().getArg(0) instanceof Local array && arrays.containsKey(array)) {
                    namedArguments(arrays.get(array)).ifPresent(named -> maps.put(result, named));
                }
                if (call.isPresent() && call.get().type().equals("init")
                        && construct(builder, view, assign, result, call.get(), maps, types)) {
                    continue;
                }
                if (call.isPresent() && call.get().type().equals("cast") && call.get().args().isEmpty()
                        && call.get().receiver() instanceof Local value
                        && invoke.get().getMethodSignature().getType() instanceof ClassType target) {
                    // (Item) value: a cast to an object type, which keeps the value.
                    JAssignStmt cast = assign.withRValue(new JCastExpr(value, target));
                    graph.replaceNode(stmt, cast);
                    types.put(result, target);
                    continue;
                }
            }
            Optional<SootMethod> target = call.flatMap(found -> target(view, found, types));
            if (target.isEmpty() && call.isPresent() && stmt instanceof JAssignStmt assign
                    && assign.getLeftOp() instanceof Local result) {
                // In a closure, an outer field is a property read on the closure that Groovy resolves on its
                // owner: the value keeps the field's type, so calls on it resolve.
                outerProperty(view, call.get(), types).ifPresent(type -> types.put(result, type));
            }
            Stmt current = stmt;
            if (target.isPresent() && (stmt instanceof JAssignStmt || stmt instanceof JInvokeStmt)) {
                List<Immediate> args = arguments(builder, view, stmt, call.get().args(), target.get());
                AbstractInvokeExpr typed = typedInvoke(view, call.get(), target.get(), args);
                current = stmt instanceof JAssignStmt assign ? assign.withRValue(typed)
                        : ((JInvokeStmt) stmt).withInvokeExpr(typed);
                graph.replaceNode(stmt, current);
            }
            if (current instanceof JAssignStmt assign && assign.getLeftOp() instanceof Local local) {
                type(assign.getRightOp(), types).ifPresent(type -> types.put(local, type));
            }
        }
    }

    /**
     * The setter a property assignment on an object of a known type runs: Groovy compiles {@code view.label = value}
     * to {@code ScriptBytecodeAdapter.setGroovyObjectProperty(value, sender, view, "label")}, or
     * {@code setProperty(..)} for an object that isn't a Groovy one.
     */
    private static Optional<SootMethod> setter(View view, AbstractInvokeExpr invoke, Map<Local, ClassType> types) {
        if (!(invoke instanceof JStaticInvokeExpr) || !invoke.getMethodSignature().getDeclClassType()
                .getFullyQualifiedName().equals(SCRIPT_BYTECODE_ADAPTER) || !PROPERTY_SETTERS.contains(
                        invoke.getMethodSignature().getName()) || invoke.getArgCount() != 4
                || !(invoke.getArg(2) instanceof Local receiver) || !types.containsKey(receiver)
                || !(invoke.getArg(3) instanceof StringConstant property) || property.getValue().isEmpty()) {
            return Optional.empty();
        }
        String name = property.getValue();
        return method(view, types.get(receiver), "set" + Character.toUpperCase(name.charAt(0)) + name.substring(1),
                1, false, List.of(argumentType(invoke.getArg(0), types)));
    }

    /**
     * The keys and values of {@code [key1, value1, key2, value2]}, when every key is a constant.
     */
    private static Optional<Map<String, Immediate>> namedArguments(Map<Integer, Immediate> elements) {
        Map<String, Immediate> named = new LinkedHashMap<>();
        for (int i = 0; elements.containsKey(i); i += 2) {
            if (!(elements.get(i) instanceof StringConstant key) || !elements.containsKey(i + 1)) {
                return Optional.empty();
            }
            named.put(key.getValue(), elements.get(i + 1));
        }
        return named.isEmpty() ? Optional.empty() : Optional.of(named);
    }

    /**
     * {@code map.get(key)}, as Groovy reads a property of a map.
     */
    private static AbstractInvokeExpr mapGet(View view, Local map, String key) {
        ClassType object = view.getIdentifierFactory().getClassType(OBJECT);
        return new JInterfaceInvokeExpr(map, view.getIdentifierFactory().getMethodSignature(
                view.getIdentifierFactory().getClassType(MAP), "get", object, List.of(object)),
                List.of(new StringConstant(key, view.getIdentifierFactory().getClassType("java.lang.String"))));
    }

    /**
     * {@code new Item(a, b)} becomes {@code new} and the constructor that fits; {@code new Item(id: 1, name: n)}
     * becomes the constructor that takes the map when the class has one ({@code @MapConstructor}'s, or one written
     * by hand), else the no-argument constructor and a setter call per named argument, as Groovy runs it (and as
     * {@code @CompileStatic} compiles it). Returns whether the call was replaced.
     */
    private static boolean construct(Body.BodyBuilder builder, View view, JAssignStmt stmt, Local result,
            GroovyCalls.Call call, Map<Local, Map<String, Immediate>> maps, Map<Local, ClassType> types) {
        Optional<ClassType> created = call.staticOwner().map(name -> view.getIdentifierFactory().getClassType(name));
        Optional<? extends SootClass> cls = created.flatMap(view::getClass);
        if (cls.isEmpty()) {
            return false;
        }
        Map<String, Immediate> named = call.args().size() == 1 && call.args().getFirst() instanceof Local map
                ? maps.get(map) : null;
        boolean takesMap = named != null && cls.get().getMethods().stream().anyMatch(method -> method.getName()
                .equals("<init>") && method.getParameterCount() == 1 && method.getParameterType(0) instanceof ClassType
                        type && MAPS.contains(type.getFullyQualifiedName()));
        if (takesMap) {
            named = null;
        }
        List<Immediate> args = named != null ? List.of() : call.args();
        List<Optional<Type>> argumentTypes = args.stream().map(arg -> argumentType(arg, types)).toList();
        Optional<? extends SootMethod> constructor = cls.get().getMethods().stream()
                .filter(method -> method.getName().equals("<init>") && !varargs(method)
                        && method.getParameterCount() == args.size() && fits(view, method, argumentTypes))
                .min(Comparator.comparing(method -> method.getSignature().toString()));
        if (constructor.isEmpty()) {
            return false;
        }
        List<FallsThroughStmt> after = new ArrayList<>();
        after.add(new JInvokeStmt(new JSpecialInvokeExpr(result, constructor.get().getSignature(), args),
                stmt.getPositionInfo()));
        if (named != null) {
            named.forEach((property, value) -> method(view, created.get(), "set" + Character.toUpperCase(
                    property.charAt(0)) + property.substring(1), 1, false, List.of(argumentType(value, types)))
                    .ifPresent(setter -> after.add(new JInvokeStmt(new JVirtualInvokeExpr(result,
                            setter.getSignature(), List.of(value)), stmt.getPositionInfo()))));
        }
        JAssignStmt allocation = stmt.withRValue(new JNewExpr(created.get()));
        MutableControlFlowGraph graph = builder.getControlFlowGraph();
        graph.replaceNode(stmt, allocation);
        graph.insertAfter(allocation, after, graph.exceptionalSuccessors(allocation));
        types.put(result, created.get());
        return true;
    }

    /**
     * The static type of a value, as far as the bytecode says.
     */
    private static Optional<ClassType> type(Value value, Map<Local, ClassType> types) {
        return switch (value) {
            case Local local -> Optional.ofNullable(types.get(local));
            case JFieldRef field -> classType(field.getFieldSignature().getType());
            case JCastExpr cast -> classType(cast.getType());
            case JNewExpr created -> Optional.of(created.getType());
            // An argument cast to choose an overload ((long) x, x as long) is passed wrapped, for Groovy to unwrap: its
            // type is the cast's, not Wrapper's, and fits as any argument does whose type isn't known.
            case AbstractInvokeExpr invoke when invoke.getMethodSignature().getName().equals("createPojoWrapper")
                    && invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                            .equals(SCRIPT_BYTECODE_ADAPTER) -> Optional.empty();
            // A dynamic call that stayed dynamic returns Object, unless it is a cast.
            case AbstractInvokeExpr invoke -> classType(invoke.getMethodSignature().getType());
            default -> Optional.empty();
        };
    }

    private static Optional<ClassType> classType(Type type) {
        return type instanceof ClassType cls && !cls.getFullyQualifiedName().equals(OBJECT) ? Optional.of(cls)
                : Optional.empty();
    }

    private Optional<SootMethod> target(View view, GroovyCalls.Call call, Map<Local, ClassType> types) {
        boolean isStatic = call.staticOwner().isPresent();
        Optional<ClassType> receiver = isStatic
                ? call.staticOwner().map(name -> view.getIdentifierFactory().getClassType(name))
                : call.typedReceiver().or(() -> type(call.receiver(), types));
        if (receiver.isEmpty() || receiver.get().getFullyQualifiedName().startsWith("groovy.")
                || receiver.get().getFullyQualifiedName().startsWith("org.codehaus.groovy.")
                || !isStatic && !(call.receiver() instanceof Local)) {
            return Optional.empty();
        }
        Set<Integer> closures = new HashSet<>();
        for (int i = 0; i < call.args().size(); i++) {
            if (type(call.args().get(i), types).filter(type -> isClosure(view, type)).isPresent()) {
                closures.add(i);
            }
        }
        String receiverName = receiver.get().getFullyQualifiedName();
        if (!closures.isEmpty() && CLOSURE_COERCING.stream().noneMatch(receiverName::startsWith)) {
            return Optional.empty();
        }
        List<Optional<Type>> argumentTypes = new ArrayList<>();
        for (int i = 0; i < call.args().size(); i++) {
            argumentTypes.add(closures.contains(i) ? Optional.empty() : argumentType(call.args().get(i), types));
        }
        return switch (call.type()) {
            // A method a closure doesn't have is its owner's: Groovy calls it on the outer object, not a proxy.
            case "invoke" -> method(view, receiver.get(), call.name(), call.args().size(), isStatic, argumentTypes,
                    closures)
                    .or(() -> outer(view, receiver.get()).flatMap(outer -> method(view, outer, call.name(),
                            call.args().size(), isStatic, argumentTypes)));
            case "getProperty" -> isStatic || !call.args().isEmpty() ? Optional.empty() : getter(view, receiver.get(),
                    call.name());
            default -> Optional.empty();
        };
    }

    /**
     * The type of {@code name} read on a closure ({@code Outer$_method_closure1}) as the outer class declares it:
     * a field, or a getter's return type.
     */
    private static Optional<ClassType> outerProperty(View view, GroovyCalls.Call call, Map<Local, ClassType> types) {
        Optional<ClassType> closure = type(call.receiver(), types);
        if (!call.type().equals("getProperty") || !call.args().isEmpty() || closure.isEmpty()
                || !isClosure(view, closure.get())) {
            return Optional.empty();
        }
        Optional<? extends SootClass> outer = outer(view, closure.get()).flatMap(view::getClass);
        if (outer.isEmpty()) {
            return Optional.empty();
        }
        Optional<ClassType> field = outer.get().getFields().stream()
                .filter(each -> each.getName().equals(call.name()) && !each.isStatic())
                .map(each -> each.getType()).findFirst().flatMap(GroovyTypedCalls::classType);
        return field.or(() -> getter(view, outer.get().getType(), call.name())
                .flatMap(getter -> classType(getter.getReturnType())));
    }

    /**
     * The class a closure ({@code Outer$_method_closure1}) is written in.
     */
    private static Optional<ClassType> outer(View view, ClassType closure) {
        String name = closure.getFullyQualifiedName();
        int nested = name.indexOf("$_");
        return nested < 0 || !isClosure(view, closure) ? Optional.empty()
                : Optional.of(view.getIdentifierFactory().getClassType(name.substring(0, nested)));
    }

    private static Optional<Type> argumentType(Immediate arg, Map<Local, ClassType> types) {
        return arg instanceof Local local ? Optional.<Type>ofNullable(types.get(local)) : Optional.of(arg.getType());
    }

    private static Optional<SootMethod> getter(View view, ClassType receiver, String property) {
        if (property.isEmpty()) {
            return Optional.empty();
        }
        String capitalized = Character.toUpperCase(property.charAt(0)) + property.substring(1);
        for (String name : List.of("get" + capitalized, "is" + capitalized, property)) {
            Optional<SootMethod> getter = method(view, receiver, name, 0, false, List.of());
            if (getter.isPresent()) {
                return getter;
            }
        }
        return Optional.empty();
    }

    /**
     * The method Groovy calls, among those with that name on the type or its supertypes: one whose parameters the
     * arguments fit (assignable, boxed, or a varargs method's trailing arguments), preferring an exact number of
     * parameters over varargs; when several fit equally, any of them if they all return the same type.
     */
    private static Optional<SootMethod> method(View view, ClassType receiver, String name, int arguments,
            boolean isStatic, List<Optional<Type>> argumentTypes) {
        return method(view, receiver, name, arguments, isStatic, argumentTypes, Set.of());
    }

    /**
     * @param closures the arguments that are closures, which Groovy coerces to the interface the parameter is (a
     *        {@code Function}, a {@code Consumer}, a {@code ResponseExtractor})
     */
    private static Optional<SootMethod> method(View view, ClassType receiver, String name, int arguments,
            boolean isStatic, List<Optional<Type>> argumentTypes, Set<Integer> closures) {
        List<SootMethod> candidates = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (SootClass cls : supertypes(view, receiver)) {
            for (SootMethod method : cls.getMethods()) {
                // The nearest declaration of each signature: subtypes come first.
                if (method.getName().equals(name) && method.isStatic() == isStatic && !method.isPrivate()
                        && fits(view, method, argumentTypes) && takesInterfaces(view, method, closures)
                        && seen.add(method.getSubSignature().toString())) {
                    candidates.add(method);
                }
            }
        }
        List<SootMethod> exact = candidates.stream().filter(method -> method.getParameterCount() == arguments
                && !varargs(method)).toList();
        List<SootMethod> best = exact.isEmpty() ? candidates : exact;
        if (best.size() <= 1) {
            return best.stream().findFirst();
        }
        boolean sameResult = best.stream().map(SootMethod::getReturnType).distinct().count() == 1;
        return sameResult ? best.stream().min(Comparator.comparing(method -> method.getSignature().toString()))
                : Optional.empty();
    }

    /**
     * Whether the method takes an interface at each of those positions, as a closure passed there is coerced to.
     */
    private static boolean takesInterfaces(View view, SootMethod method, Set<Integer> positions) {
        for (int position : positions) {
            if (position >= method.getParameterCount() || !(method.getParameterType(position) instanceof ClassType
                    parameter) || !view.getClass(parameter).map(SootClass::isInterface).orElse(false)) {
                return false;
            }
        }
        return true;
    }

    private static boolean fits(View view, SootMethod method, List<Optional<Type>> argumentTypes) {
        int parameters = method.getParameterCount();
        boolean varargs = varargs(method);
        if (argumentTypes.size() != parameters && !(varargs && argumentTypes.size() >= parameters - 1)) {
            return false;
        }
        for (int i = 0; i < argumentTypes.size(); i++) {
            Type parameter = varargs && i >= parameters - 1
                    && !(argumentTypes.size() == parameters && argumentTypes.get(i).orElse(null) instanceof ArrayType)
                    ? ((ArrayType) method.getParameterType(parameters - 1)).getElementType()
                    : method.getParameterType(i);
            if (argumentTypes.get(i).isPresent() && !assignable(view, argumentTypes.get(i).get(), parameter)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether Groovy can pass a value of this type: the same type, a supertype, or any object type for a primitive
     * (boxed) or {@code null}.
     */
    private static boolean assignable(View view, Type argument, Type parameter) {
        if (argument.equals(parameter) || parameter instanceof ClassType object
                && object.getFullyQualifiedName().equals(OBJECT)) {
            return true;
        }
        if (argument instanceof NullType) {
            return !(parameter instanceof PrimitiveType);
        }
        if (argument instanceof PrimitiveType && parameter instanceof PrimitiveType) {
            // Groovy widens and narrows numbers.
            return true;
        }
        if (argument instanceof PrimitiveType || parameter instanceof PrimitiveType) {
            // Boxing: the other side is a wrapper (or Number, Comparable, ...).
            Type boxed = argument instanceof PrimitiveType ? parameter : argument;
            return boxed instanceof ClassType wrapper && wrapper.getFullyQualifiedName().startsWith("java.lang.");
        }
        return argument instanceof ClassType cls && supertypes(view, cls).stream()
                .anyMatch(type -> type.getType().equals(parameter));
    }

    /**
     * The type, then its superclasses and interfaces, nearest first.
     */
    private static List<SootClass> supertypes(View view, ClassType type) {
        List<SootClass> found = new ArrayList<>();
        Deque<ClassType> queue = new ArrayDeque<>(List.of(type));
        Set<ClassType> seen = new HashSet<>();
        while (!queue.isEmpty() && found.size() < MAX_SUPERTYPES) {
            ClassType next = queue.removeFirst();
            if (!seen.add(next)) {
                continue;
            }
            Optional<? extends SootClass> cls = view.getClass(next);
            if (cls.isEmpty()) {
                continue;
            }
            found.add(cls.get());
            cls.get().getSuperclass().ifPresent(queue::add);
            queue.addAll(cls.get().getInterfaces());
        }
        return found;
    }

    private static boolean isClosure(View view, ClassType type) {
        return supertypes(view, type).stream()
                .anyMatch(cls -> cls.getType().getFullyQualifiedName().equals(CLOSURE));
    }

    private static AbstractInvokeExpr typedInvoke(View view, GroovyCalls.Call call, SootMethod target,
            List<Immediate> args) {
        if (target.isStatic()) {
            return new JStaticInvokeExpr(target.getSignature(), args);
        }
        Local receiver = (Local) call.receiver();
        boolean onInterface = view.getClass(target.getDeclaringClassType()).map(SootClass::isInterface)
                .orElse(false);
        return onInterface ? new JInterfaceInvokeExpr(receiver, target.getSignature(), args)
                : new JVirtualInvokeExpr(receiver, target.getSignature(), args);
    }

    /**
     * The call's arguments for the method: Groovy passes a varargs method's trailing arguments one by one, where
     * javac builds the array, so the array is built here before the call, as javac would.
     */
    private static List<Immediate> arguments(Body.BodyBuilder builder, View view, Stmt stmt, List<Immediate> args,
            SootMethod target) {
        int fixed = target.getParameterCount() - 1;
        if (!varargs(target) || args.size() == target.getParameterCount()
                && args.getLast().getType() instanceof ArrayType) {
            return args;
        }
        ArrayType arrayType = (ArrayType) target.getParameterType(fixed);
        Local array = new Local("$groovyVarargs" + builder.getLocals().size(), arrayType);
        builder.addLocal(array);
        List<FallsThroughStmt> fill = new ArrayList<>();
        fill.add(new JAssignStmt(array, new JNewArrayExpr(arrayType.getElementType(),
                IntConstant.getInstance(args.size() - fixed), view.getIdentifierFactory()), stmt.getPositionInfo()));
        for (int i = fixed; i < args.size(); i++) {
            fill.add(new JAssignStmt(new JArrayRef(array, IntConstant.getInstance(i - fixed)), args.get(i),
                    stmt.getPositionInfo()));
        }
        builder.getControlFlowGraph().insertBefore(stmt, fill,
                builder.getControlFlowGraph().exceptionalSuccessors(stmt));
        List<Immediate> packed = new ArrayList<>(args.subList(0, fixed));
        packed.add(array);
        return packed;
    }

    private static boolean varargs(SootMethod method) {
        return MethodModifier.isVarargs(method.getModifiers()) && method.getParameterCount() > 0
                && method.getParameterType(method.getParameterCount() - 1) instanceof ArrayType;
    }
}
