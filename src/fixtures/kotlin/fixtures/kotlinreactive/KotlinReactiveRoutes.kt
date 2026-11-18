package fixtures.kotlinreactive

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.router
import reactor.core.publisher.Mono

data class Team(val name: String)

data class Squad(val label: String)

@Component
class Squads {

    fun first(): Squad = Squad("core")
}

@Component
class TeamHandler(private val squads: Squads) {

    fun list(request: ServerRequest): Mono<ServerResponse> = ServerResponse.ok().bodyValue(Team("core"))

    /** The response is built from a Squad's label: lineage goes through bodyValueAndAwait. */
    suspend fun find(request: ServerRequest): ServerResponse =
        ServerResponse.ok().bodyValueAndAwait(Team(squads.first().label))
}

/** The Kotlin router DSLs: router { } (Mono handlers) and coRouter { } (suspend handlers). */
@Configuration
class KotlinReactiveRoutes {

    @Bean
    fun routes(handler: TeamHandler) = router {
        "/directory".nest {
            GET("/teams", handler::list)
        }
        POST("/directory/teams") { ServerResponse.ok().build() }
    }

    @Bean
    fun coRoutes(handler: TeamHandler) = coRouter {
        GET("/co/teams/{id}", handler::find)
        DELETE("/co/teams/{id}") { ServerResponse.noContent().buildAndAwait() }
    }
}
