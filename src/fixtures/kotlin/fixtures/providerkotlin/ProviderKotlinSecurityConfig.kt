package fixtures.providerkotlin

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/** The Kotlin DSL: HTTP Basic, checked by the chain's own manager of a provider of the application's. */
@Configuration
@EnableWebSecurity
class ProviderKotlinSecurityConfig {

    @Bean
    fun api(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            httpBasic { }
            authenticationManager = ProviderManager(DirectoryProvider())
        }
        return http.build()
    }
}

class DirectoryProvider : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication = authentication

    override fun supports(authentication: Class<*>): Boolean = true
}

@RestController
class ProviderKotlinController {

    @GetMapping("/directory")
    fun directory(): String = "directory"
}
