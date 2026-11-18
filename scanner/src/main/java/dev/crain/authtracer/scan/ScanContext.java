package dev.crain.authtracer.scan;

import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.HasAnnotation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

/**
 * The loaded application plus lookups shared by framework modules.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class ScanContext {

    private static final Logger log = LoggerFactory.getLogger(ScanContext.class);

    private final ScanInput input;
    private final JavaView view;
    private final List<JavaSootClass> applicationClasses;
    private final Set<String> applicationClassNames = new HashSet<>();
    private final ClassFileMetadata classFiles;
    private final ConfigurationProperties properties;
    private final TypeRelations types;
    private final Map<String, List<AnnotationUsage>> metaAnnotations = new ConcurrentHashMap<>();
    private final Map<String, Boolean> annotatedClasses = new ConcurrentHashMap<>();
    private final Map<String, List<JavaSootMethod>> annotatedMethods = new ConcurrentHashMap<>();
    private final Set<String> limitsHit = ConcurrentHashMap.newKeySet();
    private final Set<String> outsidePackages = ConcurrentHashMap.newKeySet();
    private final Map<String, Boolean> ownClasses = new ConcurrentHashMap<>();
    private final Map<Class<?>, Object> shared = new ConcurrentHashMap<>();

    ScanContext(ScanInput input, JavaView view, List<JavaSootClass> applicationClasses) {
        this.input = input;
        this.view = view;
        this.applicationClasses = applicationClasses;
        applicationClasses.forEach(cls -> applicationClassNames.add(cls.getName()));
        this.classFiles = new ClassFileMetadata(input.classDirs(), input.libraries());
        this.properties = ConfigurationProperties.load(input.resourceDirs());
        this.types = new TypeRelations(view, applicationClasses);
    }

    public ScanInput input() {
        return input;
    }

    /**
     * Tells that a reader stopped at one of its limits, once per place: what it didn't read past there isn't in the
     * graph (or is an Opaque node, where the reader makes one).
     *
     * @param what what stopped, e.g. "The request path's walk"
     * @param where the method, filter, template or file it stopped in
     */
    public void limit(String what, int limit, String where) {
        if (limitsHit.add(what + " " + where)) {
            log.warn("Scanning {}: {} stopped at its limit of {} in {}; what lies past it isn't read", input.service(),
                    what, limit, where);
        }
    }

    /**
     * A call into one of the service's own classes that {@code --packages} leaves out: the walk treats it as a
     * library's, so the checks and calls in it aren't read. Warned once per class.
     */
    public void outsidePackages(ClassType type, String called) {
        String name = type.getFullyQualifiedName();
        if (input.packagePrefixes().isEmpty() || input.includes(name)) {
            return;
        }
        boolean own = ownClasses.computeIfAbsent(name, found -> input.classDirs().stream()
                .anyMatch(dir -> Files.isRegularFile(dir.resolve(found.replace('.', '/') + ".class"))));
        if (own && outsidePackages.add(name)) {
            log.warn("Scanning {}: a path calls {}, in a class of the service outside the packages scanned ({}); it"
                    + " is read as a library's, so its checks and calls are not on the path", input.service(), called,
                    input.packagePrefixes());
        }
    }

    /**
     * How many of the service's classes outside {@code --packages} a path called into.
     */
    public int outsidePackages() {
        return outsidePackages.size();
    }

    /**
     * How many places a reader stopped at a limit in this scan.
     */
    public int limitsHit() {
        return limitsHit.size();
    }

    /**
     * What a framework module reads once per scan and several of its readers ask: made on first use, then the same.
     */
    public <T> T shared(Class<T> kind, java.util.function.Supplier<T> make) {
        return kind.cast(shared.computeIfAbsent(kind, key -> make.get()));
    }

    public JavaView view() {
        return view;
    }

    public List<JavaSootClass> applicationClasses() {
        return applicationClasses;
    }

    public boolean isApplication(ClassType type) {
        return applicationClassNames.contains(type.getFullyQualifiedName());
    }

    public Optional<JavaSootClass> findClass(ClassType type) {
        return view.getClass(type);
    }

    public Optional<JavaSootClass> findClass(String className) {
        return view.getClass(type(className));
    }

    public ClassType type(String className) {
        return view.getIdentifierFactory().getClassType(className);
    }

    public Optional<JavaSootMethod> findMethod(MethodSignature signature) {
        return view.getMethod(signature);
    }

    /**
     * Application subtypes of a type.
     */
    public List<ClassType> subtypesOf(ClassType type) {
        return types.subtypesOf(type);
    }

    /**
     * Superclasses, nearest first, ending before {@code java.lang.Object}.
     */
    public List<ClassType> superClassesOf(ClassType type) {
        return types.superClassesOf(type);
    }

    /**
     * Every interface the type implements, directly or indirectly.
     */
    public List<ClassType> interfacesOf(ClassType type) {
        return types.interfacesOf(type);
    }

    public ClassFileMetadata classFiles() {
        return classFiles;
    }

    public ConfigurationProperties properties() {
        return properties;
    }

    /**
     * Finds an annotation on the element, directly or as a meta-annotation (e.g. {@code @Service} carries
     * {@code @Component}). The usage returned is the one closest to the element, with its own values.
     */
    public Optional<AnnotationUsage> findAnnotation(HasAnnotation element, String annotationName) {
        for (AnnotationUsage annotation : element.getAnnotations()) {
            if (Annotations.name(annotation).equals(annotationName)) {
                return Optional.of(annotation);
            }
        }
        for (AnnotationUsage annotation : element.getAnnotations()) {
            for (AnnotationUsage meta : metaAnnotations(Annotations.name(annotation))) {
                if (Annotations.name(meta).equals(annotationName)) {
                    return Optional.of(meta);
                }
            }
        }
        return Optional.empty();
    }

    public boolean hasAnnotation(HasAnnotation element, String annotationName) {
        return findAnnotation(element, annotationName).isPresent();
    }

    /**
     * Whether some application class has the annotation, directly or as a meta-annotation, e.g.
     * {@code @EnableAutoConfiguration} (which {@code @SpringBootApplication} carries).
     */
    public boolean anyClassAnnotated(String annotationName) {
        return annotatedClasses.computeIfAbsent(annotationName,
                name -> applicationClasses.stream().anyMatch(cls -> hasAnnotation(cls, name)));
    }

    /**
     * The application's methods with the annotation, directly or as a meta-annotation, in class order and then in
     * the order each class declares them (decision 0089: the order Spring registers a configuration's {@code @Bean}
     * methods in); found once per annotation.
     */
    public List<JavaSootMethod> methodsAnnotated(String annotationName) {
        return annotatedMethods.computeIfAbsent(annotationName, name -> applicationClasses.stream()
                .flatMap(cls -> cls.getMethods().stream().filter(method -> hasAnnotation(method, name))
                        .sorted(Comparator.comparingInt(method -> classFiles.declarationIndex(method.getSignature()))))
                .toList());
    }

    /**
     * Every annotation reachable from the given annotation type through meta-annotations, nearest first.
     */
    public List<AnnotationUsage> metaAnnotations(String annotationName) {
        return metaAnnotations.computeIfAbsent(annotationName, this::collectMetaAnnotations);
    }

    private List<AnnotationUsage> collectMetaAnnotations(String annotationName) {
        List<AnnotationUsage> found = new ArrayList<>();
        Set<String> seen = new HashSet<>(Set.of(annotationName));
        Deque<String> queue = new ArrayDeque<>(List.of(annotationName));
        while (!queue.isEmpty()) {
            String current = queue.removeFirst();
            if (current.startsWith("java.lang.annotation.") || current.startsWith("kotlin.")) {
                continue;
            }
            Optional<JavaSootClass> annotationClass = findClass(current);
            if (annotationClass.isEmpty()) {
                continue;
            }
            for (AnnotationUsage meta : annotationClass.get().getAnnotations()) {
                String metaName = Annotations.name(meta);
                if (seen.add(metaName)) {
                    found.add(meta);
                    queue.addLast(metaName);
                }
            }
        }
        return List.copyOf(found);
    }
}
