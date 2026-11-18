package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.AuthorizationLocation.Scope;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0120: the checks of an authorization library AuthTracer doesn't know, as the service's
 * {@code authtracer.yaml} or the organisation's file describes them by their shape. An annotation rule's check runs
 * where Spring's method security would, through the bean's proxy, before the method; a call rule's check runs at the
 * call, before what follows, and the call throws when it denies. The requirement is the rule's SpEL with each
 * {@code {name}} replaced by the annotation's attribute (its default when it isn't given) or the call's argument
 * ({@code {arg0}}); a placeholder with several values (an array, varargs) gives one requirement per value, any or all
 * of them. A value AuthTracer can't read leaves the check opaque, with a finding.
 */
@Supports(Feature.STRUCTURE_RULES)
final class StructureRules {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{(\\w+)}");
    private static final String ANNOTATION = "annotation ";
    private static final String CALL = "call ";

    private final ScanContext context;
    private final GraphBuilder graph;
    private final SpelRequirements spel;
    private final List<ProvidedFact> annotationRules;
    private final List<ProvidedFact> callRules;

    StructureRules(ScanContext context, GraphBuilder graph, SpelRequirements spel) {
        this.context = context;
        this.graph = graph;
        this.spel = spel;
        List<ProvidedFact> rules = context.input().facts().of(ProvidedFact.Kind.RULE);
        this.annotationRules = rules.stream().filter(rule -> rule.subject().startsWith(ANNOTATION)).toList();
        this.callRules = rules.stream().filter(rule -> rule.subject().startsWith(CALL)).toList();
    }

    /**
     * The annotations the rules match, by their names.
     */
    List<String> annotations() {
        return annotationRules.stream().map(rule -> rule.subject().substring(ANNOTATION.length())).toList();
    }

    /**
     * The check an annotation rule's annotation makes on the method it was found for (on the method, or on its
     * class): applied by a proxy, so a call on this skips it.
     */
    AuthorizationLocation annotated(JavaSootMethod method, String annotationName, AnnotationUsage annotation) {
        ProvidedFact rule = annotationRules.stream().filter(candidate -> candidate.subject().equals(ANNOTATION
                + annotationName)).findFirst().orElseThrow();
        Map<String, String> defaults = context.classFiles().annotationDefaults(annotationName);
        Map<String, List<String>> values = new LinkedHashMap<>();
        for (String name : placeholders(rule)) {
            List<String> given = Annotations.strings(annotation, name);
            values.put(name, !given.isEmpty() ? given
                    : Optional.ofNullable(defaults.get(name)).map(List::of).orElse(List.of()));
        }
        String key = MethodNames.key(method.getSignature());
        CodeRef target = MethodNames.codeRef(method.getSignature());
        String simpleName = "@" + MethodNames.simpleName(annotationName);
        return graph.node(new AuthorizationLocation("location:METHOD:" + key + ":rule:" + simpleName,
                mechanism(rule, simpleName), Scope.METHOD, Phase.PRE, requirement(rule, values, key, target), target,
                null, null, Denial.THROW, true));
    }

    /**
     * A call rule's check, at a call in the application to the method it matches (or one overriding it).
     */
    Optional<AuthorizationLocation> call(JavaSootMethod caller, AbstractInvokeExpr invoke, CodeRef site) {
        for (ProvidedFact rule : callRules) {
            if (!matches(rule.subject().substring(CALL.length()), invoke.getMethodSignature())) {
                continue;
            }
            Map<String, List<String>> values = new LinkedHashMap<>();
            for (String name : placeholders(rule)) {
                List<String> read = List.of();
                if (name.matches("arg\\d+")) {
                    int index = Integer.parseInt(name.substring("arg".length()));
                    read = index < invoke.getArgCount() ? argument(caller, invoke.getArg(index)) : List.of();
                }
                values.put(name, read);
            }
            String where = MethodNames.key(caller.getSignature());
            String simpleName = MethodNames.simpleName(invoke.getMethodSignature().getDeclClassType()
                    .getFullyQualifiedName()) + "#" + invoke.getMethodSignature().getName();
            return Optional.of(graph.node(new AuthorizationLocation("location:METHOD:" + site.key() + ":rule:"
                    + simpleName + "@" + site.line(), mechanism(rule, simpleName), Scope.METHOD, Phase.PRE,
                    requirement(rule, values, where, site), site, null, null, Denial.THROW, false)));
        }
        return Optional.empty();
    }

    /**
     * Whether a call rule matches the method itself: the library's check, which the rule stands for.
     */
    boolean describes(JavaSootMethod method) {
        return callRules.stream().anyMatch(rule -> matches(rule.subject().substring(CALL.length()),
                method.getSignature()));
    }

    private static String mechanism(ProvidedFact rule, String what) {
        return "Rule " + what + " (" + rule.origin() + ")";
    }

    private static Set<String> placeholders(ProvidedFact rule) {
        Set<String> names = new LinkedHashSet<>();
        Matcher matcher = PLACEHOLDER.matcher(rule.requirement());
        while (matcher.find()) {
            names.add(matcher.group(1));
        }
        return names;
    }

    /**
     * {@code com.acme.Guard#require} for any of its overloads, or {@code com.acme.Guard#require(java.lang.String)}
     * for one; a call on a subtype (an implementation, a subclass) counts.
     */
    private boolean matches(String pattern, MethodSignature method) {
        int hash = pattern.indexOf('#');
        int paren = pattern.indexOf('(');
        String owner = pattern.substring(0, hash);
        String name = pattern.substring(hash + 1, paren < 0 ? pattern.length() : paren);
        if (!method.getName().equals(name) || !SpringBeans.assignable(context, method.getDeclClassType(),
                Set.of(owner))) {
            return false;
        }
        if (paren < 0) {
            return true;
        }
        String parameters = pattern.substring(paren + 1, pattern.length() - 1).replace(" ", "");
        return String.join(",", method.getParameterTypes().stream().map(Type::toString).toList()).equals(parameters);
    }

    /**
     * What a call passes for a placeholder: a string or int constant, an enum constant's name, or each element of a
     * varargs array; empty when it isn't a constant.
     */
    private static List<String> argument(JavaSootMethod caller, Value value) {
        if (value instanceof StringConstant constant) {
            return List.of(constant.getValue());
        }
        if (value instanceof IntConstant constant) {
            return List.of(String.valueOf(constant.getValue()));
        }
        if (!(value instanceof Local local) || !caller.hasBody()) {
            return List.of();
        }
        Optional<Value> definition = Locals.definition(caller.getBody(), local);
        if (definition.isPresent() && definition.get() instanceof JNewArrayExpr) {
            List<String> elements = new ArrayList<>();
            for (Value element : Locals.elements(caller.getBody(), local)) {
                List<String> read = argument(caller, element);
                if (read.size() != 1) {
                    return List.of();
                }
                elements.add(read.getFirst());
            }
            return elements;
        }
        return definition.flatMap(found -> found instanceof JStaticFieldRef field
                // An enum constant, by the name Spring would read it by (name()).
                ? Optional.of(field.getFieldSignature().getName())
                : found instanceof StringConstant constant ? Optional.of(constant.getValue())
                        : found instanceof IntConstant constant ? Optional.of(String.valueOf(constant.getValue()))
                        : Optional.<String>empty())
                .map(List::of).orElse(List.of());
    }

    /**
     * The rule's SpEL with its placeholders filled; with several values for one placeholder, any or all of the
     * requirements they give. A placeholder with no value leaves the check opaque, and says so.
     */
    private Requirement requirement(ProvidedFact rule, Map<String, List<String>> values, String where,
            CodeRef site) {
        List<String> unread = values.entrySet().stream().filter(entry -> entry.getValue().isEmpty())
                .map(Map.Entry::getKey).toList();
        List<String> several = values.entrySet().stream().filter(entry -> entry.getValue().size() > 1)
                .map(Map.Entry::getKey).toList();
        if (!unread.isEmpty() || several.size() > 1) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, where + " is checked by the rule for "
                    + rule.subject() + ", but " + (unread.isEmpty() ? "more than one of its placeholders has several"
                            + " values" : "what it passes for {" + String.join("}, {", unread) + "} isn't a"
                                    + " constant") + ": the check is shown as opaque", site));
            return Requirement.expression(rule.subject() + " (?)");
        }
        List<String> filled = new ArrayList<>();
        List<String> each = several.isEmpty() ? List.of("") : values.get(several.getFirst());
        for (String value : each) {
            String text = rule.requirement();
            for (Map.Entry<String, List<String>> entry : values.entrySet()) {
                text = text.replace("{" + entry.getKey() + "}", several.contains(entry.getKey()) ? value
                        : entry.getValue().getFirst());
            }
            filled.add(text);
        }
        String joined = filled.size() == 1 ? filled.getFirst() : "(" + String.join(rule.labels().contains("all")
                ? ") and (" : ") or (", filled) + ")";
        return spel.parse(joined);
    }
}
