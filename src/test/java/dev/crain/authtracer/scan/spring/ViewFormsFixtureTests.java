package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0035: the model a server-side form gets, from every place Spring fills it, and the template forms
 * spring-petclinic's owner pages use.
 */
class ViewFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("viewforms");

    @Test
    void theModelFromTheControllerAdviceAVoidModelAttributeMethodAndTheFormObject() {
        Map<String, String> edit = exposures("ingress:GET /owners/{ownerId}/edit");
        // currentUser from the advice, counts from the void @ModelAttribute method, owner by its conventional name;
        // fragment arguments by position and by name; th:with naming owner['new'].
        assertThat(edit).containsOnlyKeys("", "currentUser.name", "currentUser.email", "counts.owners",
                "owner.firstName", "owner.lastName", "owner.telephone", "owner.id", "owner.address.city",
                "owner.new");
        // The form object bound from the request, by its @ModelAttribute name or as the implicit form object,
        // renders the same form.
        assertThat(exposures("ingress:POST /owners/{ownerId}/edit")).isEqualTo(edit);
        assertThat(exposures("ingress:POST /owners/new")).isEqualTo(edit);
        // A Map attribute's keys are no properties: shown, with no type.
        assertThat(((Field) graph.node(Field.id("view:owners/createOrUpdateOwnerForm", "counts:owners"))
                .orElseThrow()).javaType()).isEqualTo("?");
    }

    @Test
    void aClosingTagWhoseElementIsntOpenClosesNothing() {
        // <input ..></input> inside the guarded div: what follows is still in the div, and in the form's th:object.
        Map<String, String> edit = exposures("ingress:GET /owners/{ownerId}/edit");
        assertThat(edit.get("owner.address.city")).isEqualTo("ROLE_OFFICE");
        assertThat(edit.get("owner.telephone")).isEqualTo("ROLE_OFFICE");
        assertThat(edit.get("owner.firstName")).isEqualTo("none");
    }

    @Test
    void viewsNamedBySetViewNameAndModelsHandedOverAsMapOf() {
        Map<String, String> details = exposures("ingress:GET /owners/{ownerId}");
        assertThat(details).containsKeys("owner.firstName", "owner.telephone", "owner.pets[].name",
                "owner.address.city").doesNotContainKeys("status.index", "param.q", "session.region");
        assertThat(details.get("owner.pets[].microchip")).isEqualTo("ROLE_VET");
        assertThat(exposures("ingress:GET /owners/{ownerId}/summary")).containsOnlyKeys("", "owner.lastName",
                "visits");
        // A Map model parameter's putIfAbsent; *{..} outside any th:object selects from the model.
        assertThat(exposures("ingress:GET /owners/find")).containsOnlyKeys("", "owner.lastName", "owner.firstName");
    }

    @Test
    void aRequestParamMapIsNoModel() {
        // @RequestParam Map<String, String> query isn't the model: the template's ${query} is no field. The
        // search form object is, by its @ModelAttribute name.
        assertThat(exposures("ingress:GET /owners")).containsOnlyKeys("", "owner.lastName", "search",
                "search.lastName");
    }

    @Test
    void withoutATemplateEveryModelAttributeIsShown() {
        assertThat(exposures("ingress:GET /owners/{ownerId}/print")).containsKeys("owner", "owner.firstName",
                "owner.telephone", "owner.address.city", "currentUser", "currentUser.email", "counts");
    }

    @Test
    void handlersThatRenderNoView() {
        // A forward, a void handler writing the response itself, and a @ResponseBody class's String.
        assertThat(response("ingress:GET /owners/search")).isEqualTo("java.lang.String");
        assertThat(((Ingress) graph.node("ingress:GET /owners/export").orElseThrow()).response()).isNull();
        assertThat(response("ingress:GET /api/owners/{ownerId}/name")).isEqualTo("java.lang.String");
    }

    private String response(String ingress) {
        return ((Ingress) graph.node(ingress).orElseThrow()).response().type();
    }

    private Map<String, String> exposures(String ingress) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.ingress().equals(ingress))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
    }
}
