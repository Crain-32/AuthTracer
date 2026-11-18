package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class FreeMarkerMarkupTests {

    @Test
    void directivesBecomeTheMarkupTheJspReaderReads() {
        String template = """
                <#import "/spring.ftl" as spring/>
                <#-- ${owner.ssn}
                     still a comment -->
                <#if owner.pets?has_content>
                  <#list owner.pets>
                    <#items as pet>${pet.name}<#sep>, </#items>
                  <#else>none
                  </#list>
                <#elseif owner.vip??>vip
                </#if>
                <@spring.formInput "owner.telephone"/>
                <#list owner.visits?filter(v -> v.paid) as visit>${visit.date}</#list>
                <@security.authorize access="hasRole('VET')"><p>${owner.notes}</p></@security.authorize>
                """;
        String markup = FreeMarkerMarkup.of(template);
        // Line for line.
        assertThat(markup.lines().count()).isEqualTo(template.lines().count());
        List<ViewTemplates.Read> reads = ViewTemplates.parse("owners/details", markup, fragment -> { },
                ViewTemplates.Dialect.JSP);
        assertThat(reads).extracting(ViewTemplates.Read::path).filteredOn(path -> path.startsWith("owner"))
                .containsOnly("owner.pets", "owner.pets[].name", "owner.vip", "owner.telephone", "owner.visits",
                        "owner.visits[].date", "owner.notes");
        assertThat(reads).filteredOn(read -> read.path().equals("owner.notes")).singleElement()
                .satisfies(read -> {
                    assertThat(read.guards()).containsExactly("hasRole('VET')");
                    assertThat(read.line()).isEqualTo(13);
                });
    }

    @Test
    void anEmptyAuthorizeTagGuardsNothingAndComputedNamesReadNothing() {
        String markup = FreeMarkerMarkup.of("""
                <@sec.authorize access="hasRole('ADMIN')"/>
                <p>${owner.name}</p>
                <@spring.formInput field/>
                <#include skin + "/footer.ftlh">
                """);
        List<String> fragments = new ArrayList<>();
        List<ViewTemplates.Read> reads = ViewTemplates.parse("owners/show", markup, fragments::add,
                ViewTemplates.Dialect.JSP);
        assertThat(reads).extracting(ViewTemplates.Read::path).containsExactly("owner.name");
        assertThat(reads.getFirst().guards()).isEmpty();
        assertThat(fragments).isEmpty();
    }
}
