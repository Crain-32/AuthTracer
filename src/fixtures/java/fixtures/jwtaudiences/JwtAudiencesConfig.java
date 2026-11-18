package fixtures.jwtaudiences;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The reference's audience check (OAUTH-06): the decoder takes tokens of its issuer for the orders API, or the
 * partner API whose name a local holds.
 */
@Configuration
@EnableWebSecurity
class JwtAudiencesConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation("https://idp.example.com").build();
        String partner = "partner-api";
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer("https://idp.example.com"),
                new JwtClaimValidator<List<String>>("aud", aud -> aud.contains("orders-api")),
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, aud -> aud.contains(partner))));
        return decoder;
    }
}

@RestController
class JwtAudiencesController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
