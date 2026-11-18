package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * EXPR-04 (decision 0091): the token claims an expression reads, in the shapes Spring Security's tokens offer them.
 */
class ExpressionReadsTests {

    @Test
    void claimsAreReadFromTheJwtTheTokenAndAnIntrospectedPrincipal() {
        assertThat(ExpressionReads.claims("principal.claims['aud'] == 'api' and principal.claims.tenant != null"))
                .containsExactly("aud", "tenant");
        assertThat(ExpressionReads.claims("authentication.token.getClaimAsString('dept') == 'hr'"
                + " or authentication.tokenAttributes['scope'] != null")).containsExactly("dept", "scope");
        assertThat(ExpressionReads.claims("authentication.token.issuer.host == 'idp' and principal.attributes['sub']"
                + " == #id")).containsExactly("iss", "sub");
    }

    @Test
    void whatIsntReadFromTheCallerIsNoClaim() {
        assertThat(ExpressionReads.claims("filterObject.attributes['owner'] == authentication.name")).isEmpty();
        assertThat(ExpressionReads.claims("principal.username == #subject")).isEmpty();
        assertThat(ExpressionReads.claims("hasRole(")).isEmpty();
        // Claims named at run time aren't read.
        assertThat(ExpressionReads.claims("principal.claims[#key] != null or principal.getClaim(#name) != null"))
                .isEmpty();
        assertThat(ExpressionReads.claims("authentication.details.subject == 'x'")).isEmpty();
    }
}
