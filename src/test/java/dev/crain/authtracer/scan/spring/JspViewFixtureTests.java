package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0035: JSP views, read like Thymeleaf templates.
 */
class JspViewFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jspviews");

    @Test
    void theFieldsTheJspReads() {
        Map<String, String> contacts = Exposures.of(graph).stream()
                .filter(exposure -> exposure.ingress().equals("ingress:GET /contacts"))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        assertThat(contacts).containsOnlyKeys("", "contacts", "contacts[].name", "contacts[].email",
                "contacts[].phone");
        // <security:authorize access=".."> guards what it wraps.
        assertThat(contacts.get("contacts[].phone")).contains("ROLE_SUPERVISOR");
        assertThat(contacts.get("contacts[].name")).doesNotContain("ROLE_SUPERVISOR");
        assertThat(graph.flows("ingress:GET /contacts")).contains(Flow.local("ingress:GET /contacts",
                "field:fixtures.jspviews.Contact.email", "field:view:index.contacts[]:email", FieldSource.DIRECT));
    }

    @Test
    void everyWayAnApplicationTellsSpringWhereItsJspsAre() {
        // ViewResolverRegistry.jsp() and jsp(prefix, suffix), an InternalResourceViewResolver bean set up with
        // setters or made with its prefix and suffix, and one in the servlet context's XML.
        for (String fixture : List.of("jspregistry", "jspregistrypaths", "jspresolver", "jspconstructor", "jspxml")) {
            Map<String, String> me = Exposures.of(FixtureScans.scan(fixture)).stream()
                    .filter(exposure -> exposure.ingress().equals("ingress:GET /members/me"))
                    .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
            assertThat(me).as(fixture).containsOnlyKeys("", "member.name", "member.email");
            assertThat(me.get("member.email")).as(fixture).isEqualTo("ROLE_ADMIN");
        }
    }
}
