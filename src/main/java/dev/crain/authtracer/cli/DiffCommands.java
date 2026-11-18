package dev.crain.authtracer.cli;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.AgentReport;
import dev.crain.authtracer.diff.DiffReport;
import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.diff.GraphDiff;
import dev.crain.authtracer.diff.Markdown;
import dev.crain.authtracer.diff.Policies;
import dev.crain.authtracer.diff.SarifReport;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.IdentityUsage;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.GitWorktree;
import dev.crain.authtracer.scan.ProjectScans;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * {@code diff}, {@code exposures}, {@code policies} and {@code identities}.
 */
@Supports(Feature.COMMAND_LINE)
final class DiffCommands {

    private static final Logger log = LoggerFactory.getLogger(DiffCommands.class);
    private static final JsonMapper JSON = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

    private DiffCommands() {
    }

    /**
     * Compares two graphs and exits non-zero when authorization got weaker.
     */
    @Supports({Feature.SARIF_ANNOTATIONS, Feature.AGENT_REPORT, Feature.DIFF, Feature.COMMAND_LINE})
    static int diff(CliArguments args) {
        SystemGraph base;
        SystemGraph head;
        // The services whose source is at hand, for SARIF locations: --sources service=dir,..., and the project.
        Map<String, Path> sources = new LinkedHashMap<>();
        for (String entry : args.list("sources")) {
            String[] parts = entry.split("=", 2);
            if (parts.length != 2) {
                throw new UsageException("--sources takes service=dir pairs: " + entry);
            }
            sources.put(parts[0], Path.of(parts[1]));
        }
        if (args.option("project").isPresent()) {
            Path project = Path.of(args.required("project")).toAbsolutePath().normalize();
            List<String> packages = args.list("packages");
            Optional<Path> orgFacts = args.file("org-facts");
            String service = args.option("service").orElse(null);
            String revision = args.option("revision").orElse(null);
            if (args.option("base-project").isEmpty()) {
                args.required("base-ref");
            }
            ApplicationGraph headGraph = args.option("head-ref")
                    .map(ref -> scanRevision(project, ref, service, revision, packages, orgFacts))
                    .orElseGet(() -> ProjectScans.defaultScanner()
                            .scan(ProjectScans.project(project, service, revision, packages, orgFacts)));
            // The base is the same service, whatever its own files call it.
            ApplicationGraph baseGraph = args.option("base-project")
                    .map(dir -> ProjectScans.defaultScanner().scan(ProjectScans.project(Path.of(dir),
                            headGraph.service(), "base", packages, orgFacts)))
                    .orElseGet(() -> scanRevision(project, args.required("base-ref"), headGraph.service(), null,
                            packages, orgFacts));
            Optional<SystemGraph> context = args.option("context").map(Path::of).map(GraphJson::readAny);
            base = withContext(baseGraph, context);
            head = withContext(headGraph, context);
            sources.putIfAbsent(headGraph.service(), project);
        }
        else {
            base = GraphJson.readAny(Path.of(args.required("base")));
            head = GraphJson.readAny(Path.of(args.required("head")));
        }
        DiffReport report = GraphDiff.compare(base, head);
        String markdown = report.markdown();
        args.option("report").map(Path::of).ifPresent(file -> write(file, markdown));
        args.option("json").map(Path::of).ifPresent(file -> write(file, JSON.writeValueAsString(report)));
        args.option("sarif").map(Path::of).ifPresent(file -> write(file, SarifReport.write(report, sources)));
        boolean failOnReview = args.flag("fail-on-review");
        args.option("agent-report").map(Path::of).ifPresent(file -> write(file, AgentReport.write(report, sources,
                failOnReview)));
        System.out.println(markdown);
        boolean failed = report.failed(failOnReview);
        log.info("Diff {}: {} fail, {} review, {} info", failed ? "FAILED" : "passed",
                report.count(DiffReport.Severity.FAIL), report.count(DiffReport.Severity.REVIEW),
                report.count(DiffReport.Severity.INFO));
        return failed ? CliRunner.FAILED : CliRunner.OK;
    }

    /**
     * Prints what every endpoint exposes and what a caller needs to get it.
     */
    @Supports({Feature.EXPOSURES, Feature.COMMAND_LINE})
    static int exposures(CliArguments args) {
        SystemGraph system = GraphJson.readAny(Path.of(args.required("graph")));
        Optional<String> filter = args.option("field");
        List<Exposure> exposures = Exposures.of(system).stream()
                .filter(exposure -> filter.map(f -> exposure.field().contains(f)
                        || exposure.sources().stream().anyMatch(source -> source.contains(f))).orElse(true))
                .toList();
        StringBuilder out = new StringBuilder("| Service | Endpoint | Field | Requirement | Checks | Sources |\n");
        out.append("|---|---|---|---|---|---|\n");
        for (Exposure exposure : exposures) {
            out.append("| ").append(Markdown.cell(exposure.service())).append(" | ")
                    .append(Markdown.code(exposure.endpoint())).append(" | ").append(field(exposure)).append(" | ")
                    .append(Markdown.cell(exposure.requirement())).append(" | ")
                    .append(Markdown.cell(String.join(" → ", exposure.steps().stream().map(Exposures.Step::mechanism)
                            .toList())))
                    .append(" | ").append(Markdown.cell(String.join(", ", exposure.sources().stream()
                            .map(DiffCommands::shortField).toList())))
                    .append(" |\n");
        }
        args.option("out").map(Path::of).ifPresent(file -> write(file, out.toString()));
        System.out.println(out);
        log.info("{} exposures across {} services", exposures.size(), system.services().size());
        return CliRunner.OK;
    }

    /**
     * Decisions 0025 and 0026: fields and endpoints that require less than their policies; exits non-zero when there
     * are any.
     */
    @Supports({Feature.POLICIES, Feature.COMMAND_LINE})
    static int policies(CliArguments args) {
        SystemGraph system = GraphJson.readAny(Path.of(args.required("graph")));
        List<Exposure> violating = Exposures.of(system).stream().filter(exposure -> !exposure.violations().isEmpty())
                .toList();
        StringBuilder out = new StringBuilder("| Service | Endpoint | Field | Policy | Requires | Requirement now |\n"
                + "|---|---|---|---|---|---|\n");
        for (Exposure exposure : violating) {
            for (Policies.Violation violation : exposure.violations()) {
                out.append("| ").append(Markdown.cell(exposure.service())).append(" | ")
                        .append(Markdown.code(exposure.endpoint())).append(" | ").append(field(exposure)).append(" | ")
                        .append(Markdown.cell(violation.label() + (violation.reason() == null ? ""
                                : " (" + violation.reason() + ")")))
                        .append(" | ").append(Markdown.cell(violation.requires())).append(" | ")
                        .append(Markdown.cell(exposure.requirement())).append(" |\n");
            }
        }
        args.option("out").map(Path::of).ifPresent(file -> write(file, out.toString()));
        long policies = system.services().stream().flatMap(graph -> graph.provided().stream())
                .filter(fact -> fact.kind() == ProvidedFact.Kind.POLICY || fact.kind() == ProvidedFact.Kind.ENDPOINT_POLICY)
                .map(fact -> fact.kind() + " " + fact.subject()).distinct().count();
        if (policies == 0) {
            // Nothing to break isn't the same as nothing broken: policies come with the scan's facts files.
            log.warn("The graph has no policies, so none was checked: they come from authtracer.yaml or --org-facts"
                    + " when the services are scanned");
        }
        System.out.println(violating.isEmpty() ? policies == 0 ? "No policies to check." : "No policy violations."
                : out);
        log.info("{} policies checked: {} endpoints and fields require less than them", policies, violating.size());
        return violating.isEmpty() ? CliRunner.OK : CliRunner.FAILED;
    }

    /**
     * Decision 0023: what each identity in the traces was granted and what its requests needed; with
     * {@code --fail-on-unneeded true}, exits non-zero when one holds authorities nothing needed.
     */
    @Supports({Feature.IDENTITIES, Feature.COMMAND_LINE})
    static int identities(CliArguments args) {
        SystemGraph system = GraphJson.readAny(Path.of(args.required("graph")));
        StringBuilder out = new StringBuilder("| # | Type | Requests | Needed | Not needed | Denied | Unread checks |"
                + "\n|---|---|---|---|---|---|---|\n");
        int number = 0;
        for (IdentityUsage identity : system.identities()) {
            out.append("| ").append(++number).append(" | ").append(Markdown.cell(identity.authenticationType()))
                    .append(" | ").append(identity.requests()).append(" | ")
                    .append(Markdown.cell(String.join(", ", identity.needed()))).append(" | ")
                    .append(Markdown.cell(String.join(", ", identity.unneeded()))).append(" | ")
                    .append(identity.denied()).append(" | ").append(identity.unread()).append(" |\n");
        }
        args.option("out").map(Path::of).ifPresent(file -> write(file, out.toString()));
        System.out.println(out);
        long overScoped = system.identities().stream().filter(identity -> !identity.unneeded().isEmpty()).count();
        log.info("{} identities in the traces, {} with authorities their requests didn't need", number, overScoped);
        boolean failOnUnneeded = args.flag("fail-on-unneeded");
        return failOnUnneeded && overScoped > 0 ? CliRunner.FAILED : CliRunner.OK;
    }

    /**
     * Scans the project as of another revision, in a temporary checkout named after the project.
     *
     * @param revision the revision to record, {@code null} for {@code <ref>@<commit>}
     */
    @Supports({Feature.DIFF, Feature.COMMAND_LINE})
    private static ApplicationGraph scanRevision(Path project, String ref, String service, String revision,
            List<String> packages, Optional<Path> orgFacts) {
        log.info("Checking out {} of {} to scan it", ref, project);
        try (GitWorktree worktree = GitWorktree.checkout(project, ref)) {
            Path checkout = worktree.project();
            return ProjectScans.defaultScanner().scan(ProjectScans.project(checkout, service,
                    revision != null ? revision : ref + "@" + ProjectScans.gitRevision(checkout), packages, orgFacts,
                    project.getFileName().toString()));
        }
    }

    /**
     * Puts the service's graph among the other services' graphs and relinks statically.
     */
    @Supports({Feature.DIFF, Feature.COMMAND_LINE})
    private static SystemGraph withContext(ApplicationGraph graph, Optional<SystemGraph> context) {
        List<ApplicationGraph> services = new ArrayList<>();
        context.ifPresent(system -> system.services().stream()
                .filter(other -> !other.service().equals(graph.service())).forEach(services::add));
        services.add(graph);
        return new Linker().link(services, ZipkinTraces.of(List.of()));
    }

    private static String field(Exposure exposure) {
        return exposure.field().isEmpty() ? "(endpoint)" : Markdown.code(exposure.field());
    }

    private static String shortField(String qualified) {
        return SystemGraph.serviceOf(qualified) + ":" + Field.shortName(SystemGraph.nodeOf(qualified));
    }

    private static void write(Path file, String content) {
        GraphJson.writeString(file, content);
        log.info("Wrote {}", file.toAbsolutePath());
    }
}
