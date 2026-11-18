package fixtures.jwtgroovy

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * A converter configured in dynamic Groovy: property writes on a local whose type the compiler infers are calls the
 * scan reads; the ones on a closure's untyped parameter, and the DSL call on one, aren't.
 */
@Configuration
@EnableWebSecurity
class JwtGroovyConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) {
        http.authorizeHttpRequests { it.requestMatchers('/admin/**').hasRole('ADMIN').anyRequest().authenticated() }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.jwtAuthenticationConverter(converter()) } }
        http.build()
    }

    @Bean
    JwtAuthenticationConverter converter() {
        def roles = new JwtGrantedAuthoritiesConverter()
        roles.authoritiesClaimName = 'roles'
        roles.authorityPrefix = 'ROLE_'
        def groups = new JwtGrantedAuthoritiesConverter()
        groups.with { it.authorityPrefix = 'GROUP_' }
        def converter = new JwtAuthenticationConverter()
        converter.jwtGrantedAuthoritiesConverter = new DelegatingJwtGrantedAuthoritiesConverter(roles, groups)
        converter
    }
}

@RestController
class JwtGroovyController {

    @GetMapping('/admin/users')
    String users() {
        'users'
    }
}
