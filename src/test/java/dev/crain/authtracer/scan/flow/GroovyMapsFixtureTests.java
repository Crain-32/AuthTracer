package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Groovy objects built with named arguments through a constructor that takes the map: each field gets the argument
 * of its name.
 */
class GroovyMapsFixtureTests {

    private static final String EMPLOYEE = "field:fixtures.groovymaps.Employee.";

    private final ApplicationGraph graph = FixtureScans.scan("groovymaps");

    @Test
    void aMapConstructorsFieldsGetTheArgumentsOfTheirNames() {
        assertThat(into("/employees/{id}", "EmployeeView.name")).containsExactly(EMPLOYEE + "name");
        assertThat(into("/employees/{id}", "EmployeeView.taxId")).containsExactly(EMPLOYEE + "ssn");
    }

    @Test
    void aStaticallyCompiledMapConstructorToo() {
        assertThat(into("/static/{id}", "StaticView.name")).containsExactly(EMPLOYEE + "name");
        assertThat(into("/static/{id}", "StaticView.taxId")).containsExactly(EMPLOYEE + "ssn");
    }

    @Test
    void aConstructorWrittenByHandReadsTheMapsEntriesAsProperties() {
        assertThat(into("/badges/{id}", "BadgeView.holder")).containsExactly(EMPLOYEE + "name");
        assertThat(into("/badges/{id}", "BadgeView.code")).containsExactly(EMPLOYEE + "id");
        assertThat(graph.flows("ingress:GET /badges/{id}")).extracting(Flow::source).containsOnly(FieldSource.DIRECT);
    }

    @Test
    void aMapWhoseKeysArentConstantsIsAllItsValues() {
        assertThat(into("/badges/{id}/{key}", "BadgeView.holder")).containsExactly(EMPLOYEE + "name");
        assertThat(into("/badges/{id}/{key}", "BadgeView.code")).containsExactly(EMPLOYEE + "name");
    }

    private List<String> into(String route, String field) {
        return graph.flows("ingress:GET " + route).stream()
                .filter(flow -> flow.to().equals("field:fixtures.groovymaps." + field)).map(Flow::from).toList();
    }
}
