package fixtures.groovydsl

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authorization.AuthorityAuthorizationManager
import org.springframework.security.authorization.AuthorizationManagers
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@SpringBootApplication
class GroovyApplication {
}

/**
 * Dynamic Groovy: closures coerced to Customizer, and every call resolved at run time.
 */
@Configuration
@EnableMethodSecurity
class GroovySecurityConfig {

    /** A Customizer bean written as a closure: its rules come first in every chain. */
    @Bean
    Customizer<HttpSecurity> publicStatus() {
        { HttpSecurity http -> http.authorizeHttpRequests { it.requestMatchers('/status').permitAll() } } as Customizer
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) {
        http.authorizeHttpRequests { registry ->
            registry
                .requestMatchers('/health', '/info').permitAll()
                .requestMatchers('/admin/**').hasRole('ADMIN')
                .requestMatchers(HttpMethod.POST, '/items/**').hasAuthority('SCOPE_items.write')
                .requestMatchers('/audit/**').access(AuthorizationManagers.anyOf(
                        AuthorityAuthorizationManager.hasRole('AUDITOR'),
                        AuthorityAuthorizationManager.hasRole('ADMIN')))
                .anyRequest().authenticated()
        }
        .oauth2ResourceServer { it.jwt(Customizer.withDefaults()) }
        http.build()
    }
}
