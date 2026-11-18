package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import org.junit.jupiter.api.Test;

/**
 * Decision 0097: configuration attributes as the default voters read them.
 */
class XmlReferencesTests {

    @Test
    void rolesAreAnyOfThemAndTheAuthenticatedAttributesAreAlternatives() {
        Requirement requirement = XmlReferences.attributes("ROLE_A,IS_AUTHENTICATED_REMEMBERED, ROLE_B", true);
        assertThat(requirement.kind()).isEqualTo(Kind.OR);
        // Decision 0105: AuthenticatedVoter grants IS_AUTHENTICATED_REMEMBERED to a remember-me session or a full
        // sign-in, which is authenticated.
        assertThat(requirement.operands()).containsExactly(Requirement.anyAuthority(List.of("ROLE_A", "ROLE_B")),
                Requirement.authenticated());
        assertThat(XmlReferences.attributes("IS_AUTHENTICATED_ANONYMOUSLY", true).kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void anAttributeNoVoterTakesAbstainsAndAllAbstainingDenies() {
        assertThat(XmlReferences.attributes("hasRole('A')", true).kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(XmlReferences.attributes("ROLE_A, ROLE_B", false).authorities()).containsExactly("ROLE_A");
    }
}
