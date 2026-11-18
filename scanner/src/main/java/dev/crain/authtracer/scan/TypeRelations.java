package dev.crain.authtracer.scan;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.views.JavaView;

/**
 * Supertype/subtype relations for application classes. SootUp's view hierarchy loads every class on the
 * classpath (all libraries and the JDK); the scan only needs the application's own relations, so this resolves
 * supertypes lazily and subtypes only among application classes.
 */
@Supports(Feature.APPLICATION_GRAPH)
final class TypeRelations {

    private final JavaView view;
    private final Map<ClassType, Set<ClassType>> subtypes = new HashMap<>();
    private final Map<ClassType, Optional<JavaSootClass>> classes = new HashMap<>();

    TypeRelations(JavaView view, List<JavaSootClass> applicationClasses) {
        this.view = view;
        for (JavaSootClass cls : applicationClasses) {
            classes.put(cls.getType(), Optional.of(cls));
        }
        for (JavaSootClass cls : applicationClasses) {
            for (ClassType supertype : supertypesOf(cls.getType())) {
                subtypes.computeIfAbsent(supertype, type -> new LinkedHashSet<>()).add(cls.getType());
            }
        }
    }

    /**
     * Application classes that extend or implement {@code type}, directly or indirectly.
     */
    List<ClassType> subtypesOf(ClassType type) {
        return List.copyOf(subtypes.getOrDefault(type, Set.of()));
    }

    /**
     * Superclasses, nearest first, ending before {@code java.lang.Object}.
     */
    List<ClassType> superClassesOf(ClassType type) {
        List<ClassType> chain = new ArrayList<>();
        Optional<ClassType> current = find(type).flatMap(cls -> cls.getSuperclass().map(ClassType.class::cast));
        while (current.isPresent() && !current.get().getFullyQualifiedName().equals("java.lang.Object")) {
            chain.add(current.get());
            current = find(current.get()).flatMap(cls -> cls.getSuperclass().map(ClassType.class::cast));
        }
        return chain;
    }

    /**
     * Every interface the type implements, including through superclasses and superinterfaces.
     */
    List<ClassType> interfacesOf(ClassType type) {
        Set<ClassType> interfaces = new LinkedHashSet<>();
        Deque<ClassType> queue = new ArrayDeque<>();
        queue.add(type);
        queue.addAll(superClassesOf(type));
        while (!queue.isEmpty()) {
            ClassType current = queue.removeFirst();
            for (ClassType iface : find(current).map(JavaSootClass::getInterfaces).orElse(Set.of())) {
                if (interfaces.add(iface)) {
                    queue.addLast(iface);
                }
            }
        }
        return List.copyOf(interfaces);
    }

    private Set<ClassType> supertypesOf(ClassType type) {
        Set<ClassType> supertypes = new LinkedHashSet<>(superClassesOf(type));
        supertypes.addAll(interfacesOf(type));
        return supertypes;
    }

    private Optional<JavaSootClass> find(ClassType type) {
        return classes.computeIfAbsent(type, view::getClass);
    }
}
