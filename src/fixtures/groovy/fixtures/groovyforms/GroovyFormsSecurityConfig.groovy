package fixtures.groovyforms

import jakarta.servlet.http.HttpServletRequest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.security.web.util.matcher.RegexRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController

/**
 * Dynamic Groovy's varargs calls: a method alone, several RequestMatchers, a method and several patterns, and a
 * RequestMatcher the closure reads from a field of its configuration.
 */
@Configuration
@EnableWebSecurity
class GroovyFormsSecurityConfig {

    private final RequestMatcher internalNetwork = { HttpServletRequest request ->
        request.remoteAddr.startsWith('10.')
    } as RequestMatcher

    @Bean
    SecurityFilterChain app(HttpSecurity http) {
        http.authorizeHttpRequests { registry ->
            registry
                .requestMatchers(HttpMethod.OPTIONS).permitAll()
                .requestMatchers(RegexRequestMatcher.regexMatcher('/reports/.*'),
                        PathPatternRequestMatcher.pathPattern('/exports/**')).hasRole('ANALYST')
                .requestMatchers(HttpMethod.DELETE, '/items/**', '/orders/**').hasRole('ADMIN')
                .requestMatchers(internalNetwork).hasRole('INTERNAL')
                .anyRequest().authenticated()
        }
        http.build()
    }
}

@RestController
class GroovyFormsController {

    @RequestMapping(path = '/items', method = RequestMethod.OPTIONS)
    void preflight() {
    }

    @GetMapping('/reports/{id}')
    String report(@PathVariable('id') long id) {
        'report'
    }

    @GetMapping('/exports/latest')
    String export() {
        'export'
    }

    @DeleteMapping('/orders/{id}')
    void delete(@PathVariable('id') long id) {
    }

    @GetMapping('/home')
    String home() {
        'home'
    }
}
