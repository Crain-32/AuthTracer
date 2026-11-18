package dev.crain.authtracer.cli;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.ProjectScans;
import dev.crain.authtracer.scan.ScanInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Supports(Feature.COMMAND_LINE)
@Component
@Profile(CliRunner.PROFILE)
class CliRunner implements ApplicationRunner, ExitCodeGenerator {

    static final String PROFILE = "cli";

    static final int OK = 0;
    /**
     * A verdict: authorization got weaker, a policy is broken, an identity is over-scoped.
     */
    static final int FAILED = 1;
    static final int USAGE = 2;
    /**
     * The command broke, e.g. a file it reads is malformed, a build failed or the graph couldn't be published: not a
     * verdict on authorization.
     */
    static final int ERROR = 3;

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(60);

    private static final Logger log = LoggerFactory.getLogger(CliRunner.class);

    private static final String USAGE_TEXT = """
            Usage:
              scan --project <gradle or maven project dir> [--service <name>] [--revision <rev>] [--packages <a,b>] [--org-facts <yaml>] --out <file> [--publish <authtracer url>]
              scan --classes <dirs> [--libraries <classpath>] [--resources <dirs>] --service <name> [--revision <rev>] [--facts <yaml>] [--org-facts <yaml>] --out <file>
              link --graphs <a.json,b.json> [--zipkin <url> [--lookback <minutes>] | --traces <zipkin json>] --out <file>
              diff --base <graph.json> --head <graph.json> [--report <md>] [--json <file>] [--sarif <file> --sources <service=dir,..>] [--fail-on-review true]
              diff --project <dir> (--base-ref <git ref> | --base-project <dir>) [--head-ref <ref>] [--service <name>] [--revision <rev>] [--context <system.json>] [--org-facts <yaml>] [--sarif <file>] [--agent-report <file>] [...]
              exposures --graph <graph.json|system.json> [--field <text>] [--out <md>]
              policies --graph <graph.json|system.json> [--out <md>]
              identities --graph <system.json> [--out <md>] [--fail-on-unneeded true]
            Exit codes: 0 ok, 1 failed (diff: authorization got weaker; policies: a field is exposed with less than
            its policy requires; identities: an identity holds authorities its requests didn't need), 2 usage,
            3 error (the command couldn't finish, e.g. a build failed, a file it reads is malformed, or publishing
            failed).
            """;

    /**
     * The options each command takes.
     */
    private static final Map<String, Set<String>> OPTIONS = Map.of(
            "scan", Set.of("project", "service", "revision", "packages", "org-facts", "out", "publish", "classes",
                    "libraries", "resources", "facts"),
            "link", Set.of("graphs", "zipkin", "lookback", "traces", "out"),
            "diff", Set.of("base", "head", "report", "json", "sarif", "sources", "fail-on-review", "project",
                    "base-ref", "base-project", "head-ref", "service", "revision", "packages", "context", "org-facts",
                    "agent-report"),
            "exposures", Set.of("graph", "field", "out"),
            "policies", Set.of("graph", "out"),
            "identities", Set.of("graph", "out", "fail-on-unneeded"));

    private int exitCode = OK;

    @Override
    public void run(ApplicationArguments arguments) {
        try {
            CliArguments args = CliArguments.parse(arguments.getSourceArgs());
            Set<String> known = OPTIONS.get(args.command());
            if (known != null) {
                args.only(args.command(), known);
            }
            exitCode = switch (args.command()) {
                case "scan" -> scan(args);
                case "link" -> link(args);
                case "diff" -> DiffCommands.diff(args);
                case "exposures" -> DiffCommands.exposures(args);
                case "identities" -> DiffCommands.identities(args);
                case "policies" -> DiffCommands.policies(args);
                default -> {
                    log.error("Unknown command '{}'.\n{}", args.command(), USAGE_TEXT);
                    yield USAGE;
                }
            };
        }
        catch (UsageException ex) {
            log.error("{}\n{}", ex.getMessage(), USAGE_TEXT);
            exitCode = USAGE;
        }
        catch (RuntimeException ex) {
            // Not exit code 1, which a pull-request check reads as "authorization got weaker".
            log.error("Failed: {}", ex.getMessage() != null ? ex.getMessage() : ex.toString(), ex);
            exitCode = ERROR;
        }
    }

    private int scan(CliArguments args) {
        Path out = Path.of(args.required("out"));
        Optional<Path> orgFacts = args.file("org-facts");
        ScanInput input = args.option("project")
                .map(project -> ProjectScans.project(Path.of(project), args.option("service").orElse(null),
                        args.option("revision").orElse(null), args.list("packages"), orgFacts))
                .orElseGet(() -> new ScanInput(args.required("service"),
                        args.option("revision").orElse(ProjectScans.WORKING_TREE),
                        classes(args), args.existingPaths("libraries"), args.existingPaths("resources"),
                        args.list("packages"),
                        ProvidedFacts.load(args.file("facts"), orgFacts, args.required("service"))));
        ApplicationGraph graph = ProjectScans.defaultScanner().scan(input);
        GraphJson.write(graph, out);
        log.info("Wrote {} graph (revision {}) to {}", graph.service(), graph.revision(), out.toAbsolutePath());
        Optional<String> publish = args.option("publish");
        if (publish.isPresent()) {
            return publish(graph, URI.create(publish.get()));
        }
        return OK;
    }

    @Supports({Feature.GRAPH_SERVER, Feature.COMMAND_LINE})
    private int publish(ApplicationGraph graph, URI authTracer) {
        // Under the URL's path, for an AuthTracer behind a proxy at http://host/authtracer.
        String base = authTracer.toString();
        URI target = URI.create(base.endsWith("/") ? base : base + "/").resolve("api/graphs");
        try {
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(target).timeout(REQUEST_TIMEOUT)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(GraphJson.write(graph))).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 201) {
                log.error("Publishing to {} failed with {}: {}", target, response.statusCode(), response.body());
                return ERROR;
            }
            log.info("Published {} graph to {}", graph.service(), target);
            return OK;
        }
        catch (IOException ex) {
            log.error("Can't reach AuthTracer at {}: {}", target, ex.getMessage());
            return ERROR;
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return ERROR;
        }
    }

    @Supports({Feature.SYSTEM_GRAPH, Feature.TRACE_OBSERVATIONS, Feature.COMMAND_LINE})
    private int link(CliArguments args) {
        Path out = Path.of(args.required("out"));
        List<ApplicationGraph> graphs = args.list("graphs").stream().map(Path::of).map(GraphJson::read).toList();
        if (graphs.isEmpty()) {
            throw new UsageException("Missing --graphs");
        }
        Duration lookback = Duration.ofMinutes(args.number("lookback").orElse(60L));
        TraceSource traces = args.option("traces").map(Path::of).map(ZipkinTraces::file)
                .orElseGet(() -> args.option("zipkin")
                        .map(url -> ZipkinTraces.api(URI.create(url), lookback, 1000))
                        .orElse(ZipkinTraces.of(List.of())));
        SystemGraph system = new Linker().link(graphs, traces);
        GraphJson.write(system, out);
        log.info("Wrote system graph of {} to {}", system.services().stream().map(ApplicationGraph::service)
                .toList(), out.toAbsolutePath());
        return OK;
    }

    private static List<Path> classes(CliArguments args) {
        args.required("classes");
        return args.existingPaths("classes");
    }

    @Override
    public int getExitCode() {
        return exitCode;
    }
}
