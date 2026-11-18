package fixtures.streamkotlinforms

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean

/**
 * Decision 0047: Kotlin function beans, () -> T a supplier and (T) -> R a function.
 */
@SpringBootApplication
class StreamKotlinFormsApp {

    @Bean
    fun heartbeat(): () -> String = { "up" }

    @Bean
    fun price(): (Order) -> Quote = { order -> Quote(order.id, 10) }
}

data class Order(val id: Long)

data class Quote(val orderId: Long, val cents: Long)
