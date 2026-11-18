package fixtures.kotlinforms

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.authorization.AuthorityAuthorizationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody

/**
 * The Kotlin DSL's other forms: the matcher left to its default, an address range, a Java manager, a servlet path
 * of /, and a login page and logout page of the application's own.
 */
@Configuration
@EnableWebSecurity
class KotlinFormsSecurityConfig {

    @Bean
    @Order(1)
    fun partners(http: HttpSecurity): SecurityFilterChain {
        http {
            securityMatcher("/partner/**")
            authorizeHttpRequests {
                authorize("/partner/public/**", permitAll)
                // The matcher argument defaulted: any request.
                authorize(access = authenticated)
            }
        }
        return http.build()
    }

    @Bean
    @Order(2)
    fun app(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/internal/**", hasIpAddress("10.0.0.0/8"))
                authorize("/account/**", fullyAuthenticated)
                authorize("/audit/**", AuthorityAuthorizationManager.hasRole("AUDITOR"))
                authorize("/root/**", "/", hasRole("ROOT"))
                authorize(anyRequest, authenticated)
            }
            formLogin {
                loginPage = "/signin"
                permitAll()
            }
            logout {
                logoutSuccessUrl = "/bye"
                permitAll = true
            }
        }
        return http.build()
    }
}

@Controller
class KotlinFormsController {

    @GetMapping("/partner/public/terms")
    @ResponseBody
    fun terms(): String = "terms"

    @GetMapping("/partner/orders")
    @ResponseBody
    fun partnerOrders(): String = "orders"

    @GetMapping("/internal/stats")
    @ResponseBody
    fun stats(): String = "stats"

    @GetMapping("/account/password")
    @ResponseBody
    fun password(): String = "password"

    @GetMapping("/audit/log")
    @ResponseBody
    fun audit(): String = "log"

    @GetMapping("/root/settings")
    @ResponseBody
    fun settings(): String = "settings"

    @GetMapping("/signin")
    fun signin(): String = "signin"

    @GetMapping("/bye")
    fun bye(): String = "bye"

    @GetMapping("/home")
    @ResponseBody
    fun home(): String = "home"
}
