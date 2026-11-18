package fixtures.groovylambdas

import groovy.transform.CompileStatic
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient

/**
 * A call out from a closure within a closure (`GroovyStock$_count_closure1$_closure2`): named by the method they are
 * written in.
 */
@CompileStatic
@Component
class GroovyStock {

    private final RestClient client = RestClient.create('http://stock:8080')

    String count(String sku) {
        List<String> counts = [sku].collect { String code ->
            [code].collect { String one -> client.get().uri('/stock/{sku}', one).retrieve().body(String) }.first()
        }
        counts.first()
    }
}

@CompileStatic
@RestController
class GroovyStockController {

    private final GroovyStock stock

    GroovyStockController(GroovyStock stock) {
        this.stock = stock
    }

    @GetMapping('/stock/{sku}')
    String stock(@PathVariable String sku) {
        stock.count(sku)
    }
}
