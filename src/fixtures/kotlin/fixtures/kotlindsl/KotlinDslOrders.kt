package fixtures.kotlindsl

import java.math.BigDecimal
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import org.springframework.web.client.body

data class Order(val id: Long, val customer: String, val total: BigDecimal, val cardNumber: String)

data class OrderView(val id: Long, val customer: String, val total: BigDecimal, val cardLast4: String)

data class Customer(val id: Long, val name: String)

@Component
class PaymentsClient(builder: RestClient.Builder, @Value("\${payments.base-url}") baseUrl: String) {

    private val client = builder.baseUrl(baseUrl).build()

    fun refund(id: Long): String = client.post().uri("/payments/{id}/refund", id).retrieve().body<String>()!!
}

@Service
class OrderService(private val payments: PaymentsClient) {

    @PreAuthorize("hasAuthority('SCOPE_orders.read')")
    fun find(id: Long): Order = Order(id, "ann", BigDecimal("12.50"), "4111111111111111")

    @PreAuthorize("hasRole('ADMIN')")
    fun refund(id: Long): String = payments.refund(id)

    /** A suspend function: compiled with a Continuation parameter and a static $suspendImpl body. */
    @PreAuthorize("hasAuthority('SCOPE_customers.read')")
    suspend fun customer(id: Long): Customer = Customer(id, "ann")
}

@RestController
@RequestMapping("/orders")
class OrderController(private val orders: OrderService) {

    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): OrderView = orders.find(id).let {
        OrderView(it.id, it.customer, it.total, it.cardNumber.takeLast(4))
    }

    @PostMapping("/{id}/refund")
    fun refund(@PathVariable id: Long): String = orders.refund(id)

    @GetMapping("/{id}/customer")
    suspend fun customer(@PathVariable id: Long): Customer = orders.customer(id)
}

@RestController
class OtherController {

    @GetMapping("/health")
    fun health(): String = "ok"

    @GetMapping("/admin/stats")
    fun stats(): String = "stats"

    @GetMapping("/ops/status")
    fun status(): String = "up"

    @GetMapping("/legacy/report")
    fun report(): String = "report"

    @GetMapping("/status/check")
    fun check(): String = "ok"

    @GetMapping("/internal/status")
    fun internal(): String = "ok"
}
