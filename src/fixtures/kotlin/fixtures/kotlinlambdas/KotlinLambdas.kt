package fixtures.kotlinlambdas

import java.util.Optional
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient

/**
 * A call out from a Kotlin lambda (`count$lambda$0`): named by the function it is written in.
 */
@Component
class KotlinStock {

    private val client = RestClient.create("http://stock:8080")

    fun count(sku: String): String? = Optional.of(sku)
        .map { code -> client.get().uri("/stock/{sku}", code).retrieve().body(String::class.java) }
        .orElse("0")
}

@RestController
class KotlinStockController(private val stock: KotlinStock) {

    @GetMapping("/stock/{sku}")
    fun stock(@PathVariable sku: String): String? = stock.count(sku)
}
