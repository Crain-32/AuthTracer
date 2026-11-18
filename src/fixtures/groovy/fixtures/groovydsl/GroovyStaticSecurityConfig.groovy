package fixtures.groovydsl

import groovy.transform.CompileStatic
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

/**
 * Statically compiled: a closure passed where a Customizer goes, and a Java-style lambda.
 */
@CompileStatic
@Configuration
class GroovyStaticSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain reports(HttpSecurity http) {
        http.securityMatcher('/reports/**')
            .authorizeHttpRequests { it.requestMatchers('/reports/public').permitAll().anyRequest().hasRole('REPORTS') }
        http.build()
    }

    @Bean
    @Order(2)
    SecurityFilterChain exports(HttpSecurity http) {
        http.securityMatcher('/exports/**')
            .authorizeHttpRequests(registry -> registry.anyRequest().hasRole('EXPORTS'))
        http.build()
    }
}
