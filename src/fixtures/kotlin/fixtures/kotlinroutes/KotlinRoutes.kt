package fixtures.kotlinroutes

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.coRouter

data class Stats(val users: Long)

data class Profile(val name: String)

/** Open, as Spring's Kotlin plugin makes components: a suspend function's body is its static $suspendImpl. */
@Component
open class AdminHandler {

    open suspend fun stats(request: ServerRequest): ServerResponse = ServerResponse.ok().bodyValueAndAwait(Stats(1))

    suspend fun profile(request: ServerRequest): ServerResponse =
        ServerResponse.ok().bodyValueAndAwait(Profile("ann"))
}

/** The coRouter DSL's path(..) and accept(..) predicates, each nesting routes. */
@Configuration
class KotlinRoutes {

    @Bean
    fun adminRoutes(handler: AdminHandler) = coRouter {
        path("/admin").nest {
            GET("/stats", handler::stats)
        }
        accept(MediaType.APPLICATION_JSON).nest {
            GET("/profile", handler::profile)
        }
    }
}
