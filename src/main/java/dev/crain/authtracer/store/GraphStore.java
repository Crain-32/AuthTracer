package dev.crain.authtracer.store;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Repository;

/**
 * Graph snapshots, stored as JSON. Every scan or link is kept, so earlier revisions stay available for diffs.
 */
@Supports(Feature.GRAPH_SERVER)
@Repository
public class GraphStore {

    private static final String APPLICATION = "APPLICATION";
    private static final String SYSTEM = "SYSTEM";

    public record Snapshot(long id, String kind, String service, String revision, Instant createdAt) {
    }

    private final JdbcClient jdbc;

    public GraphStore(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Snapshot save(ApplicationGraph graph) {
        return insert(APPLICATION, graph.service(), graph.revision(), GraphJson.write(graph));
    }

    public Snapshot save(SystemGraph system) {
        String revisions = system.services().stream().map(graph -> graph.service() + "@" + graph.revision())
                .collect(Collectors.joining(","));
        return insert(SYSTEM, null, revisions, GraphJson.write(system));
    }

    public List<Snapshot> list() {
        return jdbc.sql("select id, kind, service, revision, created_at from graph_snapshot order by id desc")
                .query((rs, row) -> new Snapshot(rs.getLong("id"), rs.getString("kind"), rs.getString("service"),
                        rs.getString("revision"), rs.getTimestamp("created_at").toInstant()))
                .list();
    }

    public Optional<ApplicationGraph> latest(String service) {
        return jdbc.sql("select content from graph_snapshot where kind = ? and service = ? order by id desc limit 1")
                .params(APPLICATION, service).query(String.class).optional().map(GraphJson::read);
    }

    public Optional<ApplicationGraph> application(String service, String revision) {
        return jdbc.sql("select content from graph_snapshot where kind = ? and service = ? and revision = ?"
                        + " order by id desc limit 1")
                .params(APPLICATION, service, revision).query(String.class).optional().map(GraphJson::read);
    }

    /**
     * The newest graph of every service.
     */
    public List<ApplicationGraph> latestApplications() {
        return jdbc.sql("select content from graph_snapshot where id in (select max(id) from graph_snapshot"
                        + " where kind = ? group by service) order by service")
                .params(APPLICATION).query(String.class).list().stream().map(GraphJson::read).toList();
    }

    public Optional<SystemGraph> latestSystem() {
        return jdbc.sql("select content from graph_snapshot where kind = ? order by id desc limit 1")
                .params(SYSTEM).query(String.class).optional().map(GraphJson::readSystem);
    }

    private Snapshot insert(String kind, String service, String revision, String content) {
        Instant now = Instant.now();
        GeneratedKeyHolder keys = new GeneratedKeyHolder();
        jdbc.sql("insert into graph_snapshot (kind, service, revision, created_at, content) values (?, ?, ?, ?, ?)")
                .params(kind, service, revision, Timestamp.from(now), content)
                .update(keys, "id");
        return new Snapshot(keys.getKey().longValue(), kind, service, revision, now);
    }
}
