package dev.crain.authtracer.api;

import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.store.GraphStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@Supports(Feature.GRAPH_SERVER)
@RestController
@RequestMapping("/api")
class GraphController {

    private static final Logger log = LoggerFactory.getLogger(GraphController.class);

    private final GraphStore store;
    private final Linker linker;
    private final TraceSource traces;

    GraphController(GraphStore store, Linker linker, TraceSource traces) {
        this.store = store;
        this.linker = linker;
        this.traces = traces;
    }

    /**
     * Stores a scanned graph, once {@link GraphValidation} finds it readable.
     */
    @PostMapping("/graphs")
    ResponseEntity<GraphStore.Snapshot> publish(@RequestBody ApplicationGraph graph) {
        try {
            GraphValidation.check(graph);
        }
        catch (IllegalArgumentException ex) {
            log.info("Rejected a graph of {}: {}", graph.service(), ex.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
        GraphStore.Snapshot snapshot = store.save(graph);
        log.info("Stored graph of {} at revision {} ({} nodes, {} findings) as snapshot {}", graph.service(),
                graph.revision(), graph.nodes().size(), graph.findings().size(), snapshot.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(snapshot);
    }

    @GetMapping("/graphs")
    List<GraphStore.Snapshot> list() {
        List<GraphStore.Snapshot> snapshots = store.list();
        log.info("Listed {} graph snapshots", snapshots.size());
        return snapshots;
    }

    @GetMapping("/graphs/{service}")
    ResponseEntity<ApplicationGraph> graph(@PathVariable String service,
            @RequestParam(required = false) String revision) {
        log.info("Graph of {} requested (revision {})", service, revision == null ? "latest" : revision);
        Optional<ApplicationGraph> graph = revision == null ? store.latest(service)
                : store.application(service, revision);
        if (graph.isEmpty()) {
            log.info("No graph of {} (revision {}) is stored", service, revision == null ? "any" : revision);
        }
        return ResponseEntity.of(graph);
    }

    /**
     * Links the newest graph of every service with the trace store's recent traces, and stores the result. When the
     * trace store can't be read, the services are linked statically only.
     */
    @Supports({Feature.TRACE_OBSERVATIONS, Feature.GRAPH_SERVER})
    @PostMapping("/system/link")
    ResponseEntity<SystemGraph> link() {
        List<ApplicationGraph> graphs = store.latestApplications();
        if (graphs.isEmpty()) {
            log.info("Link requested, but no graphs are stored yet");
            return ResponseEntity.unprocessableContent().build();
        }
        // The graph posted last for each service, whichever revision it is.
        log.info("Linking the graphs posted last: {}", graphs.stream().map(graph -> graph.service() + "@"
                + graph.revision()).toList());
        SystemGraph system = linker.link(graphs, services -> {
            try {
                return traces.traces(services);
            }
            catch (RuntimeException ex) {
                log.warn("Can't read traces, so the services are linked without them: {}", ex.getMessage());
                return List.of();
            }
        });
        GraphStore.Snapshot snapshot = store.save(system);
        log.info("Stored system graph of {} as snapshot {}", snapshot.revision(), snapshot.id());
        return ResponseEntity.ok(system);
    }

    @GetMapping("/system")
    ResponseEntity<SystemGraph> system() {
        log.info("Latest system graph requested");
        Optional<SystemGraph> system = store.latestSystem();
        if (system.isEmpty()) {
            log.info("No system graph is stored yet: POST /api/system/link makes one");
        }
        return ResponseEntity.of(system);
    }
}
