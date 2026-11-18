package fixtures.groovyclients

import org.springframework.boot.restclient.RestTemplateBuilder
import org.springframework.http.HttpMethod
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import org.springframework.web.service.annotation.GetExchange

/**
 * Dynamic Groovy HTTP calls: with an untyped (def) argument, which fits the typed method; and with a closure for a
 * response extractor, which Groovy coerces at run time, so the call stays dynamic.
 */
interface StockApi {

    @GetExchange('/stock/{sku}')
    String stock(@PathVariable('sku') String sku)
}

@RestController
class StockController {

    private final StockApi api
    private final RestTemplate template

    StockController(StockApi api, RestTemplateBuilder builder) {
        this.api = api
        this.template = builder.build()
    }

    @GetMapping('/stock/{sku}')
    String stock(@PathVariable('sku') sku) {
        api.stock(sku)
    }

    @GetMapping('/legacy')
    String legacy() {
        template.execute('http://legacy:8080/stock', HttpMethod.GET, null) { response -> response.body.text }
    }
}
