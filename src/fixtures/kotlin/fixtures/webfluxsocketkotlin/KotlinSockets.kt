package fixtures.webfluxsocketkotlin

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.HandlerMapping
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping
import org.springframework.web.reactive.socket.WebSocketHandler
import org.springframework.web.reactive.socket.WebSocketSession
import reactor.core.publisher.Mono

/**
 * A WebFlux WebSocket handler mapped in Kotlin, with `mapOf(path to handler)`.
 */
@Configuration
class KotlinSockets {

    @Bean
    fun sockets(): HandlerMapping = SimpleUrlHandlerMapping(mapOf("/quotes" to QuotesHandler()), -1)
}

class QuotesHandler : WebSocketHandler {

    override fun handle(session: WebSocketSession): Mono<Void> =
        session.send(session.receive().map { session.textMessage("quote") })
}
