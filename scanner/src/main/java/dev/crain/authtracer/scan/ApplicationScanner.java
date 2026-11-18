package dev.crain.authtracer.scan;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.provided.ProvidedFacts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.interceptor.BodyInterceptor;
import sootup.interceptors.BytecodeBodyInterceptors;
import sootup.interceptors.TypeAssigner;
import sootup.core.model.SourceType;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JrtFileSystemAnalysisInputLocation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.views.JavaView;

/**
 * Scans one application's bytecode into its application-local AuthZ graph.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class ApplicationScanner {

    private static final Logger log = LoggerFactory.getLogger(ApplicationScanner.class);

    private final List<FrameworkModule> modules;

    public ApplicationScanner(List<FrameworkModule> modules) {
        this.modules = List.copyOf(modules);
    }

    /**
     * SootUp's defaults minus {@link TypeAssigner}: it builds the view's full type hierarchy, which loads every
     * class of every library and the JDK. The scan reads def/use and invoke signatures, not inferred local types.
     */
    private static final List<BodyInterceptor> INTERCEPTORS = BytecodeBodyInterceptors.Default.getBodyInterceptors()
            .stream()
            .filter(interceptor -> !(interceptor instanceof TypeAssigner))
            .toList();
    /**
     * The application's own code also gets its dynamic Groovy calls typed where the types are known.
     */
    private static final List<BodyInterceptor> APPLICATION_INTERCEPTORS = Stream.concat(INTERCEPTORS.stream(),
            Stream.of(new GroovyTypedCalls())).toList();

    public ApplicationGraph scan(ScanInput input) {
        long start = System.currentTimeMillis();
        input.classDirs().stream().filter(dir -> !Files.isDirectory(dir)).forEach(dir -> log.warn(
                "Scanning {}: class directory {} isn't there; nothing is read from it", input.service(), dir));
        List<AnalysisInputLocation> applicationLocations = input.classDirs().stream()
                .filter(Files::isDirectory)
                .map(dir -> (AnalysisInputLocation) new OrderedMembers(new JavaClassPathAnalysisInputLocation(
                        dir.toString(), SourceType.Application, APPLICATION_INTERCEPTORS)))
                .toList();
        List<AnalysisInputLocation> locations = new ArrayList<>(applicationLocations);
        if (!input.libraries().isEmpty()) {
            locations.add(new OrderedMembers(new JavaClassPathAnalysisInputLocation(classPath(input.libraries()),
                    SourceType.Library, INTERCEPTORS)));
        }
        locations.add(new OrderedMembers(new JrtFileSystemAnalysisInputLocation(SourceType.Library, INTERCEPTORS)));
        JavaView view = new JavaView(locations);

        List<JavaSootClass> applicationClasses = applicationLocations.stream()
                .flatMap(location -> location.getClassSources(view))
                .map(source -> source.getClassType())
                .filter(type -> input.includes(type.getFullyQualifiedName()))
                .distinct()
                .flatMap(type -> view.getClass(type).stream())
                .sorted(Comparator.comparing(JavaSootClass::getName))
                .toList();

        ScanContext context = new ScanContext(input, view, applicationClasses);
        GraphBuilder graph = new GraphBuilder(input.service(), input.revision());
        if (applicationClasses.isEmpty()) {
            // An empty graph would read as a service with nothing to protect, and its diff as endpoints removed.
            String message = "No application classes were read from " + input.classDirs()
                    + (input.packagePrefixes().isEmpty() ? "" : " in packages " + input.packagePrefixes())
                    + ": the graph is empty because the scan saw nothing, not because the service has no endpoints";
            log.warn("Scanning {}: {}", input.service(), message);
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, message, null));
        }
        boolean applied = false;
        for (FrameworkModule module : modules) {
            if (module.applies(context)) {
                module.scan(context, graph);
                applied = true;
            }
            else {
                log.info("Scanning {}: {} doesn't apply (its framework isn't on the classpath of {} libraries)",
                        input.service(), module.getClass().getSimpleName(), input.libraries().size());
            }
        }
        if (!applied && !applicationClasses.isEmpty()) {
            String message = "None of the frameworks AuthTracer reads is on the classpath ("
                    + input.libraries().size() + " libraries): no entry point or check was looked for";
            log.warn("Scanning {}: {}", input.service(), message);
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, message, null));
        }
        // Decision 0106: what an opaque requirement stands for, as a digest of its code.
        OpaqueCode.digest(context, graph);
        applyFieldFacts(input.facts(), graph);
        unmatchedFacts(input.service(), input.facts(), graph);
        // Decision 0089 (amended): findings name a lambda by the method it is written in.
        graph.renameFindings(new EnclosingMethods(context)::named);
        ApplicationGraph result = graph.build();
        log.info("Scanned {} ({} application classes) in {} ms: {} nodes, {} edges, {} findings{}", input.service(),
                applicationClasses.size(), System.currentTimeMillis() - start, result.nodes().size(),
                result.edges().size(), result.findings().size(), (context.limitsHit() == 0 ? ""
                        : "; stopped at a reader's limit in " + context.limitsHit() + " places (warned above)")
                        + (context.outsidePackages() == 0 ? "" : "; called " + context.outsidePackages()
                                + " of its classes outside the packages scanned, read as libraries (warned above)"));
        return result;
    }

    /**
     * A fact the service's own file (or the Org's override for it) states about a field, method or ingress the graph
     * hasn't: a typo, or something the scan doesn't see. Its labels, policies or check then apply to nothing, so it is
     * said. Org-wide facts are about every service, so one matching nothing here is expected.
     */
    @Supports({Feature.PROVIDED_FACTS, Feature.FINDING_OPAQUE_CONFIG})
    private static void unmatchedFacts(String service, ProvidedFacts facts, GraphBuilder graph) {
        Set<String> ids = graph.nodes().stream().map(node -> node.id()).collect(Collectors.toSet());
        for (ProvidedFact fact : facts.all()) {
            if (fact.origin() == ProvidedFact.Origin.ORG) {
                continue;
            }
            String expected = switch (fact.kind()) {
                case SENSITIVE, DECLASSIFY -> fact.subject();
                case CHECK -> "location:METHOD:" + fact.subject() + ":provided";
                case REQUIREMENT -> "location:HTTP_REQUEST:provided:" + fact.subject();
                case POLICY, ENDPOINT_POLICY, RULE -> null;
            };
            boolean unmatched = expected != null ? !ids.contains(expected)
                    : fact.kind() == ProvidedFact.Kind.RULE && ids.stream().noneMatch(id -> id.contains(":rule:")
                            && id.contains(ruleMarker(fact.subject())));
            if (unmatched) {
                String message = fact.origin() + " " + fact.kind().name().toLowerCase(Locale.ROOT) + " fact on "
                        + fact.subject() + " matches nothing in the graph, so it applies to nothing: check the name"
                        + " against the graph's ids";
                log.warn("Scanning {}: {}", service, message);
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, message,
                        CodeRef.ofClass(ProvidedFacts.LOCAL_FILE)));
            }
        }
    }

    /**
     * What a rule's checks' ids hold (decision 0120): {@code @RequiresPermission} for an annotation rule,
     * {@code #require@} for a call rule.
     */
    private static String ruleMarker(String subject) {
        String matched = subject.substring(subject.indexOf(' ') + 1);
        if (subject.startsWith("annotation ")) {
            return "@" + matched.substring(matched.lastIndexOf('.') + 1);
        }
        String method = matched.substring(matched.indexOf('#') + 1);
        return "#" + (method.contains("(") ? method.substring(0, method.indexOf('(')) : method) + "@";
    }

    /**
     * Sensitivity labels and declassification are properties of fields, whatever framework produced them.
     */
    @Supports({Feature.PROVIDED_FACTS, Feature.FINDING_PROVIDED_CONFLICT})
    private static void applyFieldFacts(ProvidedFacts facts, GraphBuilder graph) {
        List<Field> fields = graph.nodes().stream().filter(Field.class::isInstance).map(Field.class::cast).toList();
        for (Field field : fields) {
            Field updated = field;
            Optional<ProvidedFact> sensitive = facts.about(ProvidedFact.Kind.SENSITIVE, field.id());
            if (sensitive.isPresent()) {
                updated = updated.withLabels(sensitive.get().labels());
            }
            if (facts.about(ProvidedFact.Kind.DECLASSIFY, field.id()).isPresent()) {
                updated = updated.declassify();
            }
            if (updated != field) {
                graph.replace(updated);
            }
        }
        graph.provided(facts.all());
        facts.conflicts().forEach(graph::finding);
    }

    private static String classPath(List<Path> entries) {
        return entries.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator));
    }
}
