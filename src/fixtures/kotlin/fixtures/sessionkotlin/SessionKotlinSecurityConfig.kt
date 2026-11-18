package fixtures.sessionkotlin

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/** The Kotlin DSL: a stateless chain with a form login, a one-time token and passkeys. */
@Configuration
@EnableWebSecurity
class SessionKotlinSecurityConfig {

    @Bean
    fun api(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            formLogin { }
            oneTimeTokenLogin { }
            webAuthn {
                rpName = "Fixture"
                rpId = "example.com"
                allowedOrigins = setOf("https://example.com")
            }
            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.STATELESS
            }
        }
        return http.build()
    }
}

@RestController
class SessionKotlinController {

    @GetMapping("/inbox")
    fun inbox(): String = "inbox"
}
