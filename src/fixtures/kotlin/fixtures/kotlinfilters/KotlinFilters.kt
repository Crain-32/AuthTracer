package fixtures.kotlinfilters

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import org.springframework.web.filter.OncePerRequestFilter

/** HTTP-17: a filter added with the Kotlin DSL's reified addFilterBefore. */
@SpringBootApplication
class KotlinFiltersApplication

@Configuration
class KotlinFilterChain {

    @Bean
    fun chain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            addFilterBefore<UsernamePasswordAuthenticationFilter>(KeyFilter())
        }
        return http.build()
    }
}

class KeyFilter : OncePerRequestFilter() {

    private val keys = RestClient.create("http://keys:8080")

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        keys.get().uri("/keys").retrieve().toBodilessEntity()
        chain.doFilter(request, response)
    }
}

@RestController
class KotlinFiltersController {

    @GetMapping("/keyed")
    fun keyed(): String = "keyed"
}
