package fixtures.sessiongroovy

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Dynamic Groovy: a stateless form login, and Basic that saves to the session in a chain that loads it.
 */
@Configuration
@EnableWebSecurity
class SessionGroovySecurityConfig {

    @Bean
    SecurityFilterChain forms(HttpSecurity http) {
        http.securityMatcher('/forms/**')
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .formLogin(Customizer.withDefaults())
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
        http.build()
    }

    @Bean
    SecurityFilterChain basic(HttpSecurity http) {
        http.authorizeHttpRequests { it.anyRequest().authenticated() }
            .httpBasic { it.securityContextRepository(new HttpSessionSecurityContextRepository()) }
        http.build()
    }
}

@RestController
class SessionGroovyController {

    @GetMapping('/forms/inbox')
    String inbox() {
        'inbox'
    }
}
