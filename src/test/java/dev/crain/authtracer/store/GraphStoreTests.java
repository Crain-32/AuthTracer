package dev.crain.authtracer.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;
import java.util.stream.IntStream;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.SystemGraph;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

class GraphStoreTests {

    @Test
    void theLatestIsTheNewestSnapshotOfThatServiceAndKind() {
        GraphStore store = new GraphStore(JdbcClient.create(database("authtracer-store-latest")));
        store.save(graph("orders", "r1"));
        store.save(graph("billing", "b1"));
        store.save(graph("orders", "r2"));
        store.save(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(graph("orders", "r1")), List.of(), List.of(),
                List.of(), List.of(), List.of()));
        store.save(graph("orders", "r3"));
        store.save(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(graph("orders", "r3"), graph("billing", "b1")),
                List.of(), List.of(), List.of(), List.of(), List.of()));

        assertThat(store.latest("orders")).hasValueSatisfying(graph -> assertThat(graph.revision()).isEqualTo("r3"));
        assertThat(store.latest("shipping")).isEmpty();
        assertThat(store.application("orders", "r2")).hasValueSatisfying(graph ->
                assertThat(graph.revision()).isEqualTo("r2"));
        assertThat(store.application("orders", "b1")).isEmpty();
        assertThat(store.latestApplications()).extracting(ApplicationGraph::service, ApplicationGraph::revision)
                .containsExactly(tuple("billing", "b1"), tuple("orders", "r3"));
        assertThat(store.latestSystem()).hasValueSatisfying(system -> assertThat(system.services()).hasSize(2));
        assertThat(store.list()).extracting(GraphStore.Snapshot::kind).containsExactly("SYSTEM", "APPLICATION",
                "SYSTEM", "APPLICATION", "APPLICATION", "APPLICATION");
    }

    @Test
    void aRevisionPublishedTwiceIsItsNewestSnapshot() {
        GraphStore store = new GraphStore(JdbcClient.create(database("authtracer-store-republished")));
        store.save(graph("orders", "r1"));
        store.save(new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "orders", "r1", 9090,
                AuthoritySource.UNKNOWN, List.of(), List.of(), List.of(), List.of(), List.of()));

        assertThat(store.application("orders", "r1")).hasValueSatisfying(graph ->
                assertThat(graph.port()).isEqualTo(9090));
    }

    private static DriverManagerDataSource database(String name) {
        DriverManagerDataSource dataSource = new DriverManagerDataSource("jdbc:h2:mem:" + name + ";DB_CLOSE_DELAY=-1");
        new ResourceDatabasePopulator(new ClassPathResource("schema.sql")).execute(dataSource);
        return dataSource;
    }

    private static ApplicationGraph graph(String service, String revision) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, revision, 8080, AuthoritySource.UNKNOWN,
                List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void aSystemOfManyServicesFitsADatabaseCreatedWithTheNarrowRevision() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:authtracer-store-test;DB_CLOSE_DELAY=-1");
        JdbcClient jdbc = JdbcClient.create(dataSource);
        // The table as earlier versions created it.
        jdbc.sql("create table graph_snapshot (id bigint auto_increment primary key, kind varchar(16) not null,"
                + " service varchar(255), revision varchar(255), created_at timestamp not null, content clob not null)")
                .update();
        ResourceDatabasePopulator schema = new ResourceDatabasePopulator(new ClassPathResource("schema.sql"));
        // Every start runs the schema.
        schema.execute(dataSource);
        schema.execute(dataSource);
        List<ApplicationGraph> services = IntStream.range(0, 12).mapToObj(i -> new ApplicationGraph(
                ApplicationGraph.SCHEMA_VERSION, "service-" + i, "main@0123456789ab-dirty", 8080 + i,
                AuthoritySource.UNKNOWN, List.of(), List.of(), List.of(), List.of(), List.of())).toList();
        GraphStore store = new GraphStore(jdbc);

        store.save(new SystemGraph(SystemGraph.SCHEMA_VERSION, services, List.of(), List.of(), List.of(), List.of(),
                List.of()));

        assertThat(store.list()).singleElement().satisfies(snapshot ->
                assertThat(snapshot.revision()).hasSizeGreaterThan(255).startsWith("service-0@main@"));
        assertThat(store.latestSystem()).hasValueSatisfying(system -> assertThat(system.services()).hasSize(12));
    }
}
