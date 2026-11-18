package fixtures.kotlindsl

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.AuthorizeHttpRequestsDsl
import org.springframework.security.config.annotation.web.HttpSecurityDsl
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.RequestMatcher

@SpringBootApplication
class KotlinDslApplication

@Configuration
@EnableMethodSecurity
class KotlinDslSecurityConfig {

    private val internalCalls = RequestMatcher { request -> request.getHeader("X-Internal") != null }

    /** The Kotlin DSL. */
    @Bean
    fun api(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize("/health", permitAll)
                authorize("/admin/**", hasRole("ADMIN"))
                authorize(HttpMethod.POST, "/orders/**", hasAuthority("SCOPE_orders.write"))
                // Matches /mvc/ops/**, so not GET /ops/status: this application's servlet path is /.
                authorize("/ops/**", "/mvc", hasRole("OPS"))
                // A matcher AuthTracer can't evaluate: never matches, rather than matching everything.
                authorize(internalCalls, permitAll)
                authorize(anyRequest, authenticated)
            }
            oauth2ResourceServer {
                jwt { }
            }
        }
        return http.build()
    }

    /** The Java lambda DSL, written in Kotlin. */
    @Bean
    @Order(1)
    fun legacy(http: HttpSecurity): SecurityFilterChain {
        http.securityMatcher("/legacy/**")
            .authorizeHttpRequests { it.anyRequest().hasRole("LEGACY") }
        return http.build()
    }
}

/** DSL beans: applied to every http { } chain ahead of its own rules, HttpSecurityDsl beans first. */
@Configuration
class KotlinDslBeans {

    @Bean
    fun statusRules(): AuthorizeHttpRequestsDsl.() -> Unit = {
        authorize("/status/**", hasRole("OPS"))
        authorize("/internal/status", hasRole("OPS"))
    }

    @Bean
    fun internalRules(): HttpSecurityDsl.() -> Unit = {
        authorizeHttpRequests {
            authorize("/internal/**", denyAll)
        }
    }
}
