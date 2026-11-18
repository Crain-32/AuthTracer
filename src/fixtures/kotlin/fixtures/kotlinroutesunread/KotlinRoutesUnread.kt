package fixtures.kotlinroutesunread

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.router
import reactor.core.publisher.Mono

@Component
class ShopHandler {

    fun list(request: ServerRequest): Mono<ServerResponse> = ServerResponse.ok().build()

    fun search(request: ServerRequest): Mono<ServerResponse> = ServerResponse.ok().build()

    fun health(request: ServerRequest): Mono<ServerResponse> = ServerResponse.ok().build()

    fun json(request: ServerRequest): Mono<ServerResponse> = ServerResponse.ok().build()

    fun beta(request: ServerRequest): Mono<ServerResponse> = ServerResponse.ok().build()
}

/**
 * Decision 0080: the router DSL's other route forms. A predicate or'ed and invoked with its handler, a path invoked
 * with its handler, path(..) and accept(..) given a handler (routes, not nests), a negated predicate, and routes a
 * helper adds.
 */
@Configuration
class KotlinRoutesUnread {

    @Bean
    fun shopRoutes(handler: ShopHandler) = router {
        (GET("/products") or GET("/catalog")).invoke(handler::list)
        "/search".invoke(handler::search)
        path("/health", handler::health)
        accept(MediaType.APPLICATION_JSON, handler::json)
        (!path("/beta/**")).invoke(handler::beta)
        add(adminRoutes(handler))
    }

    private fun adminRoutes(handler: ShopHandler) = router {
        GET("/admin/stats", handler::list)
    }
}
