package fixtures.streamkotlin

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Bean
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.stereotype.Service

/**
 * Decision 0047: a Kotlin function bean, (Order) -> Unit, is a consumer.
 */
@SpringBootApplication
@EnableMethodSecurity
class StreamKotlinApp {

    @Bean
    fun ship(warehouse: Warehouse): (Order) -> Unit = { order -> warehouse.ship(order) }
}

data class Order(val id: Long)

@Service
class Warehouse {

    @PreAuthorize("hasRole('WAREHOUSE')")
    fun ship(order: Order) {
    }
}
