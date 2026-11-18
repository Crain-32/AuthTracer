package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Mappers that call each other: a summary made while the other was unfinished isn't kept.
 */
class RecursiveMappersFixtureTests {

    private static final String FIXTURE = "field:fixtures.recursivemappers.";

    private final ApplicationGraph graph = FixtureScans.scan("recursivemappers");

    @Test
    void eachEndpointsViewsComeFromTheEmployeesFieldsWhicheverIsReadFirst() {
        assertThat(flows("/employee")).contains(
                FIXTURE + "Employee.ssn -> " + FIXTURE + "EmployeeView.ssn",
                FIXTURE + "Employee.name -> " + FIXTURE + "ManagerView.name");
        assertThat(flows("/manager")).contains(
                FIXTURE + "Employee.name -> " + FIXTURE + "ManagerView.name",
                FIXTURE + "Employee.ssn -> " + FIXTURE + "EmployeeView.ssn");
    }

    private List<String> flows(String route) {
        return graph.flows("ingress:GET " + route).stream().map(flow -> flow.from() + " -> " + flow.to()).distinct()
                .toList();
    }
}
