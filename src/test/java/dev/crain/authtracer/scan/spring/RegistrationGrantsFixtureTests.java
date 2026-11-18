package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Spring Boot 4.1.1's OAuth2ClientPropertiesMapper builds a registration without a grant type from Spring Security
 * 7.1.1's CommonOAuth2Provider or its provider's issuer, both authorization code; 7.1.1 has no password grant.
 */
class RegistrationGrantsFixtureTests {

    private final Map<String, String> credentials = FixtureScans.scan("registrationgrants").nodes(Egress.class).stream()
            .collect(Collectors.toMap(Egress::uriTemplate, egress -> egress.credentials() + " "
                    + egress.credentialsVia(), (a, b) -> a));

    @Test
    void aCommonProvidersOrAnIssuersRegistrationIsTheSignedInUsers() {
        assertThat(credentials)
                .containsEntry("/repos", "RELAY clientRegistrationId(\"github\"), the signed-in user's"
                        + " authorization_code token")
                .containsEntry("/directory", "RELAY clientRegistrationId(\"corporate\"), the signed-in user's"
                        + " authorization_code token");
    }

    @Test
    void aPasswordGrantIsNoneSpringSecurityHas() {
        assertThat(credentials.get("/ledger")).startsWith("UNKNOWN clientRegistrationId(\"legacy\")");
    }
}
