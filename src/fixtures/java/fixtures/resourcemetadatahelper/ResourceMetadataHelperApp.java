package fixtures.resourcemetadatahelper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * OAUTH-07: the resource server is configured by a helper the chain calls.
 */
@Configuration
@EnableWebSecurity
class ResourceMetadataHelperApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return Tokens.accept(http).build();
    }
}

final class Tokens {

    private Tokens() {
    }

    static HttpSecurity accept(HttpSecurity http) throws Exception {
        return http.oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
    }
}
