package fixtures.kotlinreactive

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.AuthorizeExchangeDsl
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@SpringBootApplication
class KotlinReactiveApplication

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class KotlinReactiveSecurityConfig {

    @Bean
    fun chain(http: ServerHttpSecurity): SecurityWebFilterChain = http {
        authorizeExchange {
            authorize("/public/**", permitAll)
            authorize("/admin/**", hasRole("ADMIN"))
            // The access argument defaults to authenticated.
            authorize("/reports/**")
            authorize(pathMatchers(HttpMethod.POST, "/teams/**"), hasAuthority("SCOPE_teams.write"))
            authorize(anyExchange, permitAll)
        }
        httpBasic { }
    }

    /** Applied to every http { } chain, ahead of its own rules. */
    @Bean
    fun opsRules(): AuthorizeExchangeDsl.() -> Unit = {
        authorize("/ops/**", hasRole("OPS"))
    }
}

@Service
class TeamService {

    /** Reactive method security runs on coroutines too. */
    @PreAuthorize("hasRole('LEAD')")
    suspend fun rename(id: Long): Team = Team("team-" + id)
}

@RestController
class KotlinReactiveController(private val teams: TeamService) {

    @PostMapping("/teams/{id}/rename")
    suspend fun rename(@PathVariable id: Long): Team = teams.rename(id)

    @GetMapping("/public/info")
    fun info(): Mono<String> = Mono.just("info")

    @GetMapping("/admin/users")
    fun users(): Mono<String> = Mono.just("users")

    @GetMapping("/reports/daily")
    fun daily(): Mono<String> = Mono.just("daily")

    @PostMapping("/teams/new")
    fun create(): Mono<String> = Mono.just("created")

    @GetMapping("/teams")
    fun teams(): Mono<String> = Mono.just("teams")

    @GetMapping("/ops/status")
    fun status(): Mono<String> = Mono.just("up")
}
