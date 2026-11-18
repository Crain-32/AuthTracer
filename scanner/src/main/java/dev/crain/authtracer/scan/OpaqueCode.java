package dev.crain.authtracer.scan;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Requirement;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0106: an opaque requirement (an {@link Requirement.Kind#EXPRESSION}) that stands for code AuthTracer doesn't
 * read carries a digest of that code, so the diff sees a change to it. The code is the class that decides it (its
 * {@code decidedBy}: a custom {@code AuthorizationManager}, a SpEL bean, a {@code PermissionEvaluator}), else the
 * class the check is declared in when that is code rather than an annotation's expression (rules set in a helper
 * AuthTracer doesn't follow, a manager built where {@code verify(..)} is called). A class's code is every method's
 * body (lambdas and field initializers included), its nested classes', and its application superclasses' and
 * subclasses' (a template method's override). An annotation's expression is its text: a change to it is one already.
 */
@Supports({Feature.CUSTOM_DECISIONS, Feature.REQUIREMENTS})
final class OpaqueCode {

    private final ScanContext context;
    private final Map<String, Optional<String>> digests = new HashMap<>();

    private OpaqueCode(ScanContext context) {
        this.context = context;
    }

    static void digest(ScanContext context, GraphBuilder graph) {
        OpaqueCode code = new OpaqueCode(context);
        for (Node node : List.copyOf(graph.nodes())) {
            if (node instanceof AuthorizationLocation location && location.requirement() != null) {
                Requirement digested = code.digested(location.requirement(), location);
                if (!digested.equals(location.requirement())) {
                    graph.replace(location.withRequirement(digested));
                }
            }
        }
    }

    private Requirement digested(Requirement requirement, AuthorizationLocation location) {
        if (requirement.kind() == Requirement.Kind.EXPRESSION) {
            String className = requirement.decidedBy() != null ? requirement.decidedBy().className()
                    : location.target() != null && !location.mechanism().startsWith("@")
                            ? location.target().className() : null;
            return Optional.ofNullable(className).flatMap(this::digest).map(requirement::withCode).orElse(requirement);
        }
        List<Requirement> operands = requirement.operands().stream()
                .map(operand -> digested(operand, location)).toList();
        return operands.equals(requirement.operands()) ? requirement : requirement.withOperands(operands);
    }

    private Optional<String> digest(String className) {
        return digests.computeIfAbsent(className, name -> context.findClass(name)
                .filter(found -> context.isApplication(found.getType())).map(found -> digest(found.getType())));
    }

    private String digest(ClassType type) {
        Set<String> names = new TreeSet<>();
        names.add(type.getFullyQualifiedName());
        context.superClassesOf(type).stream().filter(context::isApplication)
                .forEach(each -> names.add(each.getFullyQualifiedName()));
        context.subtypesOf(type).forEach(each -> names.add(each.getFullyQualifiedName()));
        for (JavaSootClass cls : context.applicationClasses()) {
            String name = cls.getType().getFullyQualifiedName();
            if (names.stream().anyMatch(outer -> name.startsWith(outer + "$"))) {
                names.add(name);
            }
        }
        MessageDigest sha = sha256();
        for (String name : names) {
            context.findClass(name).ifPresent(cls -> cls.getMethods().stream()
                    .sorted(Comparator.comparing(method -> method.getSignature().toString()))
                    .forEach(method -> update(sha, method)));
        }
        return java.util.HexFormat.of().formatHex(sha.digest()).substring(0, 16);
    }

    private static void update(MessageDigest sha, JavaSootMethod method) {
        sha.update(method.getSignature().toString().getBytes(StandardCharsets.UTF_8));
        if (method.hasBody()) {
            sha.update(method.getBody().toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
