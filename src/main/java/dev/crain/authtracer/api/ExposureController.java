package dev.crain.authtracer.api;

import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.store.GraphStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.core.JacksonException;

/**
 * What each endpoint exposes and what a caller needs to get it, for the stored system graph or a posted graph.
 */
@Supports(Feature.GRAPH_SERVER)
@RestController
@RequestMapping("/api")
class ExposureController {

    private static final Logger log = LoggerFactory.getLogger(ExposureController.class);

    private final GraphStore store;

    ExposureController(GraphStore store) {
        this.store = store;
    }

    @GetMapping("/system/exposures")
    ResponseEntity<List<ExposureView>> systemExposures() {
        Optional<SystemGraph> system = store.latestSystem();
        if (system.isEmpty()) {
            log.info("Exposures of the latest system graph requested, but none is stored yet");
            return ResponseEntity.notFound().build();
        }
        List<ExposureView> exposures = ExposureView.of(system.get());
        log.info("Exposures of the latest system graph requested: {} across {} services", exposures.size(),
                system.get().services().size());
        return ResponseEntity.ok(exposures);
    }

    /**
     * Exposures of an application or system graph sent in the body, e.g. a file the UI opened. Nothing is stored.
     */
    @PostMapping("/exposures")
    List<ExposureView> exposures(@RequestBody String json) {
        SystemGraph system;
        try {
            system = GraphJson.readAny(json);
            GraphValidation.check(system);
        }
        catch (IllegalArgumentException | JacksonException ex) {
            String reason = ex instanceof JacksonException jackson ? jackson.getOriginalMessage() : ex.getMessage();
            log.info("Exposures requested for a body that is not a graph: {}", reason);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, reason, ex);
        }
        List<ExposureView> exposures = ExposureView.of(system);
        log.info("Exposures of a posted graph of {} requested: {}", system.services().stream()
                .map(graph -> graph.service() + "@" + graph.revision()).toList(), exposures.size());
        return exposures;
    }
}
