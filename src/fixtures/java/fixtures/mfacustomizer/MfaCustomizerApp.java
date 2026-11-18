package fixtures.mfacustomizer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-07 customized, as the reference shows it: @EnableMultiFactorAuthentication's factory asks for a password and a
 * one-time token, and a Customizer bean adds a certificate and asks only the admin.
 */
@Configuration
@EnableWebSecurity
@EnableMultiFactorAuthentication(authorities = { FactorGrantedAuthority.PASSWORD_AUTHORITY,
        FactorGrantedAuthority.OTT_AUTHORITY })
class MfaCustomizerConfig {

    @Bean
    Customizer<AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder<Object>> additionalRequiredFactors() {
        return builder -> builder.when(authentication -> "admin".equals(authentication.getName()))
                .requireFactors(FactorGrantedAuthority.X509_AUTHORITY);
    }

    /**
     * A customizer of something else: not the factory's.
     */
    @Bean
    Customizer<HttpSecurity> headers() {
        return http -> {
            try {
                http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
            }
            catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
        };
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class MfaCustomizerController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
