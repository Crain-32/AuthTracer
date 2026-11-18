package dev.crain.authtracer.scan;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import org.junit.jupiter.api.Test;

/**
 * Dynamic Groovy calls that stay dynamic because they pass a closure, or because their overloads differ in what they
 * return: the receiver's static type and the call site's argument types say which method runs. And the calls Groovy
 * makes differently from javac: varargs one by one, a property assigned through ScriptBytecodeAdapter.
 */
class GroovyCallsFixtureTests {

    private static final String CHECK = "location:METHOD:fixtures.groovycalls.";

    private final ApplicationGraph graph = FixtureScans.scan("groovycalls");

    @Test
    void aCallPassingAClosureRunsTheMethodItNames() {
        assertThat(path(graph, "ingress:GET /batch"))
                .contains(CHECK + "ItemService#eachOf(java.util.List,groovy.lang.Closure):@PreAuthorize");
    }

    @Test
    void anInheritedMethodIsFoundOnTheSuperclass() {
        assertThat(path(graph, "ingress:GET /admin/batch"))
                .contains(CHECK + "ItemService#eachOf(java.util.List,groovy.lang.Closure):@PreAuthorize");
    }

    @Test
    void aCallOnAnInterfaceRunsItsImplementations() {
        assertThat(path(graph, "ingress:GET /audited/{id}"))
                .contains(CHECK + "LogAuditor#record(java.lang.String,groovy.lang.Closure):@PreAuthorize");
    }

    @Test
    void aStaticCallRunsTheStaticMethod() {
        assertThat(path(graph, "ingress:GET /turns/{id}")).contains(CHECK + "ItemService#find(long):@PreAuthorize");
    }

    @Test
    void amongOverloadsTheCallSitesTypesPickTheMethod() {
        assertThat(path(graph, "ingress:GET /names/{name}"))
                .contains(CHECK + "ItemService#lookup(java.lang.String):@PreAuthorize")
                .doesNotContain(CHECK + "ItemService#lookup(java.lang.CharSequence):@PreAuthorize");
    }

    @Test
    void aVarargsMethodCalledWithOneArgumentIsThatMethod() {
        assertThat(path(graph, "ingress:GET /all/{id}")).contains(CHECK + "ItemService#findAll(long[]):@PreAuthorize");
    }

    @Test
    void constantArgumentsFitAsGroovyPassesThem() {
        assertThat(path(graph, "ingress:GET /constants")).contains(CHECK + "ItemService#find(long):@PreAuthorize",
                CHECK + "ItemService#describe(fixtures.groovycalls.Item):@PreAuthorize");
    }

    @Test
    void aClosureReadsItsOwnersGetterOnlyProperty() {
        assertThat(path(graph, "ingress:GET /catalogue")).contains(CHECK + "ItemService#find(long):@PreAuthorize");
    }

    @Test
    void aCallInATryBlockIsOnThePath() {
        assertThat(path(graph, "ingress:GET /tried/{id}")).contains(CHECK + "ItemService#find(long):@PreAuthorize");
    }

    @Test
    void anAssignedPropertyHoldsWhatItWasAssigned() {
        assertThat(graph.flows("ingress:GET /views/{id}")).contains(Flow.local("ingress:GET /views/{id}",
                "field:fixtures.groovycalls.Item.name", "field:fixtures.groovycalls.ItemView.label",
                FieldSource.DIRECT));
        assertThat(graph.flows("ingress:GET /labels/{id}")).contains(Flow.local("ingress:GET /labels/{id}",
                "field:fixtures.groovycalls.Item.name", "field:fixtures.groovycalls.Label.text", FieldSource.DIRECT));
    }

    @Test
    void overloadsTheCallSiteCantTellApartAreLeftToRunTime() {
        assertThat(path(graph, "ingress:GET /report")).noneMatch(node -> node.contains("ItemService#report("));
    }

    @Test
    void aClosurePassedToAGroovyOrLibraryMethodRunsWhereItIsWritten() {
        assertThat(path(graph, "ingress:GET /items/{id}")).contains(CHECK + "ItemService#find(long):@PreAuthorize");
        assertThat(path(graph, "ingress:GET /cached/{id}")).contains(CHECK + "ItemService#find(long):@PreAuthorize");
    }
}
