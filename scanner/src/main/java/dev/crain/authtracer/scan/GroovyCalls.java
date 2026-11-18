package dev.crain.authtracer.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootMethod;

/**
 * Dynamic Groovy call sites. Groovy 4 and later compile every call outside {@code @CompileStatic} code to an
 * invokedynamic bootstrapped by {@code IndyInterface}: the call site's name is the call type ({@code invoke},
 * {@code getProperty}, {@code cast}, ...), the first bootstrap argument is the method or property name, and the
 * first argument is the receiver, a {@code Class} constant for static calls. The call site's descriptor carries
 * the receiver's static type when the compiler knows it (a typed field, parameter or local), else {@code Object}.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class GroovyCalls {

    private static final String INDY_PACKAGE = "org.codehaus.groovy.vmplugin.";

    private GroovyCalls() {
    }

    /**
     * @param type the call type: {@code invoke}, {@code getProperty}, {@code setProperty}, {@code cast}, {@code init}
     * @param receiverType the receiver's static type, {@code java.lang.Object} when the compiler did not know it
     */
    public record Call(String type, String name, Immediate receiver, List<Immediate> args, Type receiverType) {

        /**
         * The class a static call or property is on: the receiver is its {@code Class} constant.
         */
        public Optional<String> staticOwner() {
            return className(receiver);
        }

        /**
         * The receiver's static type, when the compiler knew a more specific one than {@code Object}.
         */
        public Optional<ClassType> typedReceiver() {
            return receiverType instanceof ClassType type && !type.getFullyQualifiedName().equals("java.lang.Object")
                    && staticOwner().isEmpty() ? Optional.of(type) : Optional.empty();
        }
    }

    /**
     * The application method a dynamic call names, when the receiver's type is known (a typed field, parameter or
     * local, {@code this}, or a class for a static call): the method with that name and number of parameters whose
     * parameter types match the call site, or the only one with that name and number, looking up the superclasses.
     * Calls on untyped receivers ({@code def}) are left out, as Groovy resolves them at run time.
     */
    @Supports(Feature.CALL_PATHS)
    public static Optional<JavaSootMethod> target(ScanContext context, Call call) {
        Optional<ClassType> receiver = receiverClass(context, call);
        if (!call.type().equals("invoke") || receiver.isEmpty() || !context.isApplication(receiver.get())) {
            return Optional.empty();
        }
        boolean isStatic = call.staticOwner().isPresent();
        List<ClassType> chain = new ArrayList<>(List.of(receiver.get()));
        chain.addAll(context.superClassesOf(receiver.get()));
        for (ClassType candidate : chain) {
            if (!context.isApplication(candidate)) {
                break;
            }
            List<JavaSootMethod> named = context.findClass(candidate).stream()
                    .flatMap(cls -> cls.getMethods().stream())
                    .filter(method -> method.getName().equals(call.name()) && method.isStatic() == isStatic
                            && method.getParameterCount() == call.args().size())
                    .toList();
            Optional<JavaSootMethod> exact = named.stream().filter(method -> matches(method, call)).findFirst();
            if (exact.isPresent()) {
                return exact;
            }
            if (!named.isEmpty()) {
                return named.size() == 1 ? Optional.of(named.getFirst()) : Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
     * The class the call is made on: the class of a static call, or the receiver's static type.
     */
    @Supports(Feature.CALL_PATHS)
    public static Optional<ClassType> receiverClass(ScanContext context, Call call) {
        return call.staticOwner().map(context::type).or(call::typedReceiver);
    }

    private static boolean matches(JavaSootMethod method, Call call) {
        for (int i = 0; i < call.args().size(); i++) {
            if (!method.getParameterType(i).equals(call.args().get(i).getType())) {
                return false;
            }
        }
        return true;
    }

    public static Optional<Call> of(AbstractInvokeExpr invoke) {
        if (!(invoke instanceof JDynamicInvokeExpr dynamic) || !isGroovy(dynamic) || dynamic.getArgCount() == 0
                || dynamic.getBootstrapArgCount() == 0 || !(dynamic.getBootstrapArg(0) instanceof StringConstant name)) {
            return Optional.empty();
        }
        List<Immediate> args = dynamic.getArgs();
        return Optional.of(new Call(dynamic.getMethodSignature().getName(), name.getValue(), args.getFirst(),
                args.subList(1, args.size()), dynamic.getMethodSignature().getParameterTypes().getFirst()));
    }

    private static boolean isGroovy(JDynamicInvokeExpr dynamic) {
        String bootstrap = dynamic.getBootstrapMethodSignature().getDeclClassType().getFullyQualifiedName();
        return bootstrap.startsWith(INDY_PACKAGE) && bootstrap.endsWith(".IndyInterface");
    }

    /**
     * The class a {@code ldc} class constant names.
     */
    public static Optional<String> className(Value value) {
        if (!(value instanceof ClassConstant constant)) {
            return Optional.empty();
        }
        String descriptor = constant.getValue();
        return descriptor.startsWith("L") && descriptor.endsWith(";")
                ? Optional.of(descriptor.substring(1, descriptor.length() - 1).replace('/', '.'))
                : Optional.empty();
    }
}
