package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.GenericTypes;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0035: the server-side views a {@code @Controller} handler renders, and the model they get. A handler
 * without {@code @ResponseBody} that returns a view name ({@code "owners/ownerDetails"}) or a {@code ModelAndView}
 * renders that view with its model: what it, and the helpers it hands the model ({@code Model}, or a {@code Map}
 * parameter) to, add with {@code addAttribute}/{@code addObject}/{@code put}; the controller's {@code @ModelAttribute}
 * methods; and its {@code @ModelAttribute} (or implicit form object) parameters. Redirects and forwards render nothing
 * here.
 * <p>
 * Decision 0081: the controller is the class the handler is mapped on, which may inherit it: a {@code @RestController}
 * inheriting a handler that returns a {@code String} answers with the string. Handlers that render one view with
 * different models each have their own view type, so each shows only what its model has.
 */
@Supports(Feature.VIEW_FIELDS)
final class ViewModels {

    /**
     * @param names the view names, sorted (a handler can render one of several)
     * @param attributes the model attributes by name, with their types where known
     * @param owner the view's type, e.g. {@code view:owners/details}; with the handler when other handlers render
     *        the view with another model ({@code view:owners/details (OwnerController#print)})
     */
    record View(Set<String> names, Map<String, GenericType> attributes, String owner) {

        View(Set<String> names, Map<String, GenericType> attributes) {
            this(names, attributes, "view:" + String.join(",", names));
        }
    }

    private static final String RESPONSE_BODY = "org.springframework.web.bind.annotation.ResponseBody";
    private static final String MODEL_ATTRIBUTE = "org.springframework.web.bind.annotation.ModelAttribute";
    private static final String MODEL_AND_VIEW = "org.springframework.web.servlet.ModelAndView";
    private static final String CONTROLLER_ADVICE = "org.springframework.web.bind.annotation.ControllerAdvice";
    private static final String JAX_RS_PATH = "jakarta.ws.rs.Path";
    private static final Set<String> MODELS = Set.of("org.springframework.ui.Model", "org.springframework.ui.ModelMap",
            "org.springframework.ui.ExtendedModelMap", "org.springframework.ui.ConcurrentModel",
            "org.springframework.validation.support.BindingAwareModelMap", MODEL_AND_VIEW);
    private static final String MAP = "java.util.Map";
    private static final Set<String> ADDS = Set.of("addAttribute", "addObject", "put", "putIfAbsent");
    /**
     * Parameters bound from somewhere else than the model.
     */
    private static final Set<String> NOT_MODEL = Set.of("PathVariable", "RequestParam", "RequestBody",
            "RequestHeader", "CookieValue", "RequestAttribute", "SessionAttribute", "MatrixVariable", "RequestPart",
            "AuthenticationPrincipal", "CurrentSecurityContext", "Value");
    private static final int MAX_DEPTH = 4;

    private final ScanContext context;
    private final GenericTypes types;
    private final Map<String, Optional<View>> views = new HashMap<>();

    ViewModels(ScanContext context, GenericTypes types) {
        this.context = context;
        this.types = types;
    }

    /**
     * The views the mappings render, each handler's own where they render the same view with different models.
     */
    void prepare(List<RequestMappings.Mapping> mappings) {
        Map<Set<String>, Map<Map<String, GenericType>, List<String>>> byNames = new LinkedHashMap<>();
        for (RequestMappings.Mapping mapping : mappings) {
            String key = key(mapping.handler(), mapping.receiver());
            Optional<View> view = views.computeIfAbsent(key, k -> view(mapping.handler(), mapping.receiver()));
            view.ifPresent(found -> byNames.computeIfAbsent(found.names(), names -> new LinkedHashMap<>())
                    .computeIfAbsent(found.attributes(), model -> new ArrayList<>()).add(key));
        }
        byNames.values().stream().filter(models -> models.size() > 1).forEach(models -> models.values()
                .forEach(keys -> {
                    // Named after the first handler (in sorted order) that renders it with this model.
                    String handler = keys.stream().sorted().findFirst().orElseThrow();
                    String named = handler.substring(0, handler.indexOf('('));
                    for (String key : keys) {
                        View shared = views.get(key).orElseThrow();
                        views.put(key, Optional.of(new View(shared.names(), shared.attributes(), shared.owner()
                                + " (" + named.substring(named.lastIndexOf('.') + 1) + ")")));
                    }
                }));
    }

    /**
     * @param receiver the controller that inherits the handler, {@code null} for the handler's own class
     */
    Optional<View> of(JavaSootMethod handler, ClassType receiver) {
        return views.computeIfAbsent(key(handler, receiver), key -> view(handler, receiver));
    }

    /**
     * The handler on its controller, e.g. {@code fixtures.views.OwnerController#show}.
     */
    private static String key(JavaSootMethod handler, ClassType receiver) {
        return (receiver != null ? receiver : handler.getDeclaringClassType()).getFullyQualifiedName() + "#"
                + handler.getName() + "(" + handler.getParameterTypes() + ")";
    }

    private Optional<View> view(JavaSootMethod handler, ClassType receiver) {
        Optional<JavaSootClass> controller = context.findClass(receiver != null ? receiver
                : handler.getDeclaringClassType());
        // A JAX-RS resource's String is its body, not a view's name.
        if (controller.isEmpty() || context.hasAnnotation(controller.get(), JAX_RS_PATH)
                || context.hasAnnotation(controller.get(), RESPONSE_BODY)
                || context.hasAnnotation(handler, RESPONSE_BODY) || !(handler.getReturnType() instanceof ClassType
                        returned) || !(returned.getFullyQualifiedName().equals("java.lang.String")
                                || returned.getFullyQualifiedName().equals(MODEL_AND_VIEW))) {
            return Optional.empty();
        }
        Set<String> names = new TreeSet<>();
        views(handler, names, 0);
        if (names.isEmpty()) {
            return Optional.empty();
        }
        Map<String, GenericType> attributes = new LinkedHashMap<>();
        // @ModelAttribute methods run before every handler of the controller, inherited ones too, and a
        // @ControllerAdvice's before every handler.
        List<JavaSootMethod> modelMethods = new ArrayList<>(controller.get().getMethods());
        context.superClassesOf(controller.get().getType()).stream().filter(context::isApplication)
                .flatMap(type -> context.findClass(type).stream())
                .forEach(superClass -> modelMethods.addAll(superClass.getMethods()));
        context.applicationClasses().stream().filter(advice -> context.hasAnnotation(advice, CONTROLLER_ADVICE))
                .forEach(advice -> modelMethods.addAll(advice.getMethods()));
        for (JavaSootMethod method : modelMethods) {
            Optional<AnnotationUsage> annotation = context.findAnnotation(method, MODEL_ATTRIBUTE);
            if (annotation.isPresent() && method.hasBody() && !method.equals(handler)) {
                if (method.getReturnType() instanceof ClassType) {
                    GenericType type = context.classFiles().genericReturnType(method.getSignature())
                            .orElse(new GenericType(method.getReturnType().toString(), List.of()));
                    attributes.put(name(annotation.get()).orElse(conventionalName(type)), type);
                }
                added(method, attributes, 0);
            }
        }
        parameters(handler, attributes);
        added(handler, attributes, 0);
        return Optional.of(new View(names, attributes));
    }

    /**
     * The view names a method's returns name, through the helpers that return them.
     */
    private void views(JavaSootMethod method, Set<String> names, int depth) {
        if (!method.hasBody() || depth > MAX_DEPTH) {
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt result) {
                view(method, result.getOp(), names, depth);
            }
        }
    }

    private void view(JavaSootMethod method, Value value, Set<String> names, int depth) {
        if (value instanceof StringConstant constant) {
            add(constant.getValue(), names);
            return;
        }
        if (!(value instanceof Local local)) {
            return;
        }
        // cond ? "a" : "b" assigns the local on each branch.
        for (Value definition : Locals.definitions(method.getBody(), local)) {
            if (definition instanceof StringConstant constant) {
                add(constant.getValue(), names);
            }
            else if (definition instanceof AbstractInvokeExpr invoke
                    && context.isApplication(invoke.getMethodSignature().getDeclClassType())) {
                context.findMethod(invoke.getMethodSignature()).ifPresent(helper -> views(helper, names, depth + 1));
            }
        }
        // A ModelAndView: its constructor's or setViewName's name.
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get() instanceof AbstractInstanceInvokeExpr instance
                    && instance.getBase().equals(local)
                    && instance.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(MODEL_AND_VIEW)
                    && (instance.getMethodSignature().getName().equals("<init>")
                            || instance.getMethodSignature().getName().equals("setViewName"))
                    && instance.getArgCount() > 0 && instance.getArg(0) instanceof StringConstant name) {
                add(name.getValue(), names);
            }
        }
    }

    private static void add(String view, Set<String> names) {
        if (!view.startsWith("redirect:") && !view.startsWith("forward:")) {
            names.add(view);
        }
    }

    /**
     * What a method (and the application methods it hands the model to) adds to the model.
     */
    private void added(JavaSootMethod method, Map<String, GenericType> attributes, int depth) {
        if (!method.hasBody() || depth > MAX_DEPTH) {
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
            if (found.isEmpty()) {
                continue;
            }
            AbstractInvokeExpr invoke = found.get();
            String name = invoke.getMethodSignature().getName();
            if (invoke instanceof AbstractInstanceInvokeExpr instance && isModel(method, instance.getBase())) {
                if (name.equals("<init>") && invoke.getArgCount() == 3
                        && invoke.getArg(1) instanceof StringConstant attribute) {
                    // new ModelAndView(view, "name", value)
                    attributes.put(attribute.getValue(), type(method, invoke.getArg(2)));
                }
                else if (name.equals("<init>") && invoke.getArgCount() == 2
                        && invoke.getArg(1) instanceof Local map && !isModel(method, map)) {
                    // new ModelAndView(view, map): what the method puts in the map, or Map.of(..)'s pairs.
                    mapEntries(method, map, attributes);
                }
                else if (ADDS.contains(name) && invoke.getArgCount() == 2
                        && invoke.getArg(0) instanceof StringConstant attribute) {
                    attributes.put(attribute.getValue(), type(method, invoke.getArg(1)));
                }
                else if (ADDS.contains(name) && invoke.getArgCount() == 1) {
                    GenericType type = type(method, invoke.getArg(0));
                    attributes.put(conventionalName(type), type);
                }
                continue;
            }
            if (context.isApplication(invoke.getMethodSignature().getDeclClassType())
                    && invoke.getArgs().stream().anyMatch(arg -> isModel(method, arg))) {
                context.findMethod(invoke.getMethodSignature()).ifPresent(helper -> added(helper, attributes,
                        depth + 1));
            }
        }
    }

    private void mapEntries(JavaSootMethod method, Local map, Map<String, GenericType> attributes) {
        Optional<AbstractInvokeExpr> created = Locals.definition(method.getBody(), map)
                .filter(AbstractInvokeExpr.class::isInstance).map(AbstractInvokeExpr.class::cast)
                .filter(invoke -> invoke.getMethodSignature().getName().equals("of"));
        if (created.isPresent()) {
            for (int i = 0; i + 1 < created.get().getArgCount(); i += 2) {
                if (created.get().getArg(i) instanceof StringConstant key) {
                    attributes.put(key.getValue(), type(method, created.get().getArg(i + 1)));
                }
            }
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> put = Locals.invoke(stmt);
            if (put.isPresent() && put.get() instanceof AbstractInstanceInvokeExpr instance
                    && instance.getBase().equals(map) && put.get().getArgCount() == 2
                    && Set.of("put", "putIfAbsent").contains(put.get().getMethodSignature().getName())
                    && put.get().getArg(0) instanceof StringConstant key) {
                attributes.put(key.getValue(), type(method, put.get().getArg(1)));
            }
        }
    }

    /**
     * {@code @ModelAttribute} parameters, and the form objects Spring binds and adds without one.
     */
    private void parameters(JavaSootMethod handler, Map<String, GenericType> attributes) {
        List<GenericType> generic = context.classFiles().genericParameterTypes(handler.getSignature());
        for (int i = 0; i < handler.getParameterCount(); i++) {
            if (!(handler.getParameterType(i) instanceof ClassType type)) {
                continue;
            }
            boolean modelAttribute = context.classFiles().parameterAnnotations(handler.getSignature(), i)
                    .contains(MODEL_ATTRIBUTE);
            if (boundElsewhere(handler, i) || !modelAttribute && !context.isApplication(type)) {
                continue;
            }
            GenericType parameter = i < generic.size() ? generic.get(i)
                    : new GenericType(type.getFullyQualifiedName(), List.of());
            String name = modelAttribute ? context.classFiles().parameterAnnotationValue(handler.getSignature(), i,
                    MODEL_ATTRIBUTE).filter(value -> !value.isEmpty()).orElse(conventionalName(parameter))
                    : conventionalName(parameter);
            attributes.putIfAbsent(name, parameter);
        }
    }

    /**
     * A {@code Model}, or a {@code Map} parameter bound no other way, which Spring fills with the model too
     * ({@code MapMethodProcessor}), in the handler and in the helpers it hands it to.
     */
    private boolean isModel(JavaSootMethod method, Immediate value) {
        Optional<GenericType> type = types.of(method, value);
        if (type.map(found -> MODELS.contains(found.name())).orElse(false)) {
            return true;
        }
        return type.filter(found -> found.name().equals(MAP)).isPresent() && value instanceof Local local
                && Locals.parameterIndex(method.getBody(), local).stream()
                        .anyMatch(index -> !boundElsewhere(method, index));
    }

    private boolean boundElsewhere(JavaSootMethod method, int parameter) {
        return context.classFiles().parameterAnnotations(method.getSignature(), parameter).stream()
                .anyMatch(annotation -> NOT_MODEL.contains(annotation.substring(annotation.lastIndexOf('.') + 1)));
    }

    private GenericType type(JavaSootMethod method, Immediate value) {
        return types.of(method, value).orElse(new GenericType("?", List.of()));
    }

    private static Optional<String> name(AnnotationUsage annotation) {
        return Annotations.string(annotation, "value").or(() -> Annotations.string(annotation, "name"))
                .filter(value -> !value.isEmpty());
    }

    /**
     * Spring's {@code Conventions.getVariableName}: the class's simple name, decapitalized; {@code ownerList} for a
     * collection of {@code Owner}.
     */
    private String conventionalName(GenericType type) {
        GenericType element = types.element(type);
        String simple = element.name().substring(Math.max(element.name().lastIndexOf('.'),
                element.name().lastIndexOf('$')) + 1).replace("[]", "");
        String name = simple.isEmpty() ? "value" : Character.toLowerCase(simple.charAt(0)) + simple.substring(1);
        return element == type ? name : name + "List";
    }
}
