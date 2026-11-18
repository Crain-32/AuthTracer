package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class FlowsFixtureTests {

    private static final String VIEW = "field:fixtures.flows.View.";
    private static final String SOURCE = "field:fixtures.flows.Source.";

    private final ApplicationGraph graph = FixtureScans.scan("flows");

    @Test
    void accessorReadsAreDirect() {
        assertThat(into("/view", VIEW + "direct")).containsExactly(flow(SOURCE + "first", FieldSource.DIRECT));
    }

    @Test
    void concatenationIsComputedFromEachInput() {
        assertThat(into("/view", VIEW + "concatenated")).containsExactlyInAnyOrder(
                flow(SOURCE + "first", FieldSource.COMPUTED), flow(SOURCE + "last", FieldSource.COMPUTED));
    }

    @Test
    void nestedObjectsAreComplexAndTheirFieldsKeepTheirOwnSource() {
        assertThat(into("/view", VIEW + "complex")).containsExactly(flow(SOURCE + "first", FieldSource.COMPLEX));
        assertThat(into("/view", "field:fixtures.flows.Nested.first"))
                .containsExactly(flow(SOURCE + "first", FieldSource.DIRECT));
    }

    @Test
    void branchingOnAFieldIsAnImplicitFlow() {
        assertThat(into("/view", VIEW + "band")).containsExactly(flow(SOURCE + "amount", FieldSource.COMPUTED));
    }

    @Test
    void identityHelpersStayDirectAndLibraryCallsCompute() {
        assertThat(into("/view", VIEW + "passedThrough")).containsExactly(flow(SOURCE + "secret", FieldSource.DIRECT));
        assertThat(into("/view", VIEW + "secretLength"))
                .containsExactly(flow(SOURCE + "secret", FieldSource.COMPUTED));
    }

    @Test
    void collectionsMappedWithMethodReferences() {
        Ingress views = (Ingress) graph.node("ingress:GET /views").orElseThrow();
        assertThat(views.response().type()).isEqualTo("fixtures.flows.View");
        assertThat(views.response().many()).isTrue();
        assertThat(into("/views", VIEW + "direct")).containsExactly(flow(SOURCE + "first", FieldSource.DIRECT));
    }

    @Test
    void predicatesComparatorsAndExceptionSuppliersDontReplaceTheElements() {
        for (String route : List.of("/found", "/visible", "/fallback")) {
            assertThat(into(route, VIEW + "direct")).as(route)
                    .containsExactly(flow(SOURCE + "first", FieldSource.DIRECT));
        }
    }

    @Test
    void aLookupKeyIsNotTheValueItLooksUp() {
        assertThat(into("/lookup", "field:fixtures.flows.LegacyView.name"))
                .containsExactly(flow(SOURCE + "last", FieldSource.DIRECT));
    }

    @Test
    void anAsynchronousResultIsTheResponse() {
        assertThat(((Ingress) graph.node("ingress:GET /later").orElseThrow()).response().type())
                .isEqualTo("fixtures.flows.View");
    }

    @Test
    void aFluentBuilderCarriesWhatEachCallSets() {
        assertThat(into("/order", "field:fixtures.flows.OrderDto.customer"))
                .containsExactly(flow(SOURCE + "first", FieldSource.DIRECT));
        assertThat(into("/order", "field:fixtures.flows.OrderDto.secret"))
                .containsExactly(flow(SOURCE + "secret", FieldSource.DIRECT));
    }

    @Test
    void aCollectionsElementsAreInTheResponse() {
        assertThat(((Field) graph.node("field:fixtures.flows.Shelter.pets").orElseThrow()).javaType())
                .isEqualTo("fixtures.flows.ShelterPet[]");
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.endpoint().equals("GET /shelter"))
                .extracting(Exposures.Exposure::field).contains("pets", "pets[].name", "pets[].microchip");
    }

    @Test
    void classesAreFilledThroughTheirConstructor() {
        assertThat(into("/legacy", "field:fixtures.flows.LegacyView.name"))
                .containsExactly(flow(SOURCE + "last", FieldSource.DIRECT));
    }

    @Test
    void beansAreFilledThroughTheirSetters() {
        assertThat(into("/bean", "field:fixtures.flows.BeanView.name"))
                .containsExactly(flow(SOURCE + "first", FieldSource.DIRECT));
        assertThat(into("/bean", "field:fixtures.flows.BeanView.label")).containsExactlyInAnyOrder(
                flow(SOURCE + "first", FieldSource.COMPUTED), flow(SOURCE + "last", FieldSource.COMPUTED));
    }

    @Test
    void gettersAreMatchedByTheNameTheyAreDeclaredWith() {
        ApplicationGraph accessors = FixtureScans.scan("accessors");
        assertThat(accessors.flows("ingress:GET /member").stream().map(flow -> flow.from() + " -> " + flow.to()))
                .containsExactlyInAnyOrder(
                        "field:fixtures.accessors.Member.active -> field:fixtures.accessors.MemberView.active",
                        "field:fixtures.accessors.Member.verified -> field:fixtures.accessors.MemberView.verified");
    }

    @Test
    void switchingOnAFieldIsAnImplicitFlow() {
        assertThat(FixtureScans.scan("accessors").flows("ingress:GET /tier").stream()
                .filter(flow -> flow.to().equals("field:fixtures.accessors.Tier.name"))
                .map(flow -> flow(flow.from(), flow.source())))
                .containsExactly(flow("field:fixtures.accessors.Member.level", FieldSource.COMPUTED));
    }

    @Test
    void anArrayResponseIsManyOfItsElements() {
        Ingress members = (Ingress) FixtureScans.scan("accessors").node("ingress:GET /members").orElseThrow();
        assertThat(members.response().type()).isEqualTo("fixtures.accessors.MemberView");
        assertThat(members.response().many()).isTrue();
    }

    @Test
    void jsonNamesFollowJsonProperty() {
        Field concatenated = (Field) graph.node(VIEW + "concatenated").orElseThrow();
        assertThat(concatenated.jsonName()).isEqualTo("display_name");
        assertThat(((Field) graph.node(VIEW + "direct").orElseThrow()).jsonName()).isEqualTo("direct");
        // A class's @JsonNaming names the rest.
        assertThat(((Field) graph.node("field:fixtures.flows.SnakeView.firstName").orElseThrow()).jsonName())
                .isEqualTo("first_name");
        assertThat(((Field) graph.node("field:fixtures.flows.SnakeView.homeURL").orElseThrow()).jsonName())
                .isEqualTo("home_url");
        assertThat(((Field) graph.node("field:fixtures.flows.SnakeView.nickName").orElseThrow()).jsonName())
                .isEqualTo("nick");
        // Kotlin puts the annotation on the primary constructor's parameter.
        ApplicationGraph kotlin = FixtureScans.scan("kotlindto");
        assertThat(((Field) kotlin.node("field:fixtures.kotlindto.Member.name").orElseThrow()).jsonName())
                .isEqualTo("display_name");
        assertThat(((Field) kotlin.node("field:fixtures.kotlindto.Member.email").orElseThrow()).jsonName())
                .isEqualTo("email");
    }

    private List<String> into(String route, String field) {
        return graph.flows("ingress:GET " + route).stream().filter(flow -> flow.to().equals(field))
                .map(flow -> flow(flow.from(), flow.source())).toList();
    }

    private static String flow(String from, FieldSource source) {
        return source + " " + from;
    }
}
