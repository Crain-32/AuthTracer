package dev.crain.authtracer.graph;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.deser.DeserializationProblemHandler;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

@Supports({Feature.APPLICATION_GRAPH, Feature.SYSTEM_GRAPH})
public final class GraphJson {

    private static final Logger log = LoggerFactory.getLogger(GraphJson.class);
    private static final Set<String> UNKNOWN = ConcurrentHashMap.newKeySet();

    /**
     * Tolerant on read, so graphs written by older versions (missing newer properties) still load. A property this
     * version doesn't know comes from a newer one: it is dropped, and said once.
     */
    private static final JsonMapper MAPPER = JsonMapper.builder()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .addHandler(new DeserializationProblemHandler() {
                @Override
                public boolean handleUnknownProperty(DeserializationContext context, JsonParser parser,
                        ValueDeserializer<?> deserializer, Object beanOrClass, String property) {
                    String owner = (beanOrClass instanceof Class<?> type ? type : beanOrClass.getClass())
                            .getSimpleName();
                    if (UNKNOWN.add(owner + "." + property)) {
                        log.warn("A graph property this AuthTracer doesn't know, {}.{}, is left out: the graph was"
                                + " written by a newer version, and what that property says isn't compared", owner,
                                property);
                    }
                    return false;
                }
            })
            .build();

    private GraphJson() {
    }

    public static String write(ApplicationGraph graph) {
        return MAPPER.writeValueAsString(graph) + System.lineSeparator();
    }

    public static void write(ApplicationGraph graph, Path file) {
        writeString(file, write(graph));
    }

    public static ApplicationGraph read(String json) {
        ApplicationGraph graph = MAPPER.readValue(json, ApplicationGraph.class);
        newer("The graph of " + graph.service(), graph.schemaVersion(), ApplicationGraph.SCHEMA_VERSION);
        return graph;
    }

    public static ApplicationGraph read(Path file) {
        return read(readString(file));
    }

    public static String write(SystemGraph system) {
        return MAPPER.writeValueAsString(system) + System.lineSeparator();
    }

    public static void write(SystemGraph system, Path file) {
        writeString(file, write(system));
    }

    public static SystemGraph readSystem(String json) {
        SystemGraph system = MAPPER.readValue(json, SystemGraph.class);
        newer("A system graph", system.schemaVersion(), SystemGraph.SCHEMA_VERSION);
        system.services().forEach(graph -> newer("The graph of " + graph.service(), graph.schemaVersion(),
                ApplicationGraph.SCHEMA_VERSION));
        return system;
    }

    /**
     * A graph a newer AuthTracer wrote may mean something this one reads otherwise: said, as it is still read.
     */
    private static void newer(String what, int version, int known) {
        if (version > known && UNKNOWN.add("schemaVersion " + version)) {
            log.warn("{} has schema version {}, newer than this AuthTracer's {}: what changed since is read as {}"
                    + " reads it, or left out", what, version, known, known);
        }
    }

    /**
     * A system graph file as is, or an application graph file as a system of one service.
     */
    public static SystemGraph readAny(Path file) {
        return readAny(readString(file));
    }

    /**
     * A system graph as is, or an application graph as a system of one service.
     *
     * @throws IllegalArgumentException when the JSON is neither
     */
    public static SystemGraph readAny(String json) {
        JsonNode tree = MAPPER.readTree(json);
        if (tree.has("services")) {
            return readSystem(json);
        }
        if (!tree.has("nodes")) {
            throw new IllegalArgumentException("Not an application or system graph: it has neither 'nodes' nor"
                    + " 'services'");
        }
        return SystemGraph.of(read(json));
    }

    private static String readString(Path file) {
        try {
            return Files.readString(file);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Writes a file, creating its directory.
     */
    public static void writeString(Path file, String content) {
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.writeString(file, content);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
