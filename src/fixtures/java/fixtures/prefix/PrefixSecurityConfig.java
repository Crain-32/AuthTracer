package fixtures.prefix;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class PrefixSecurityConfig {

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("PERM_");
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/dsl").hasRole("ADMIN")
                        .requestMatchers("/factory").access(AuthorityAuthorizationManager.hasRole("OPS"))
                        .requestMatchers("/expression").access(new WebExpressionAuthorizationManager("hasRole('LEGACY')"))
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}
