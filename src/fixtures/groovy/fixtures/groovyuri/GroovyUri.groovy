package fixtures.groovyuri

import org.springframework.http.HttpMethod
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestTemplate
import org.springframework.web.util.UriBuilder

/**
 * Dynamic Groovy client chains that pass a closure, which Groovy coerces to the functional interface the method takes:
 * a uri closure on the implicit parameter, one on a typed parameter, one that adds a path AuthTracer can't read, a
 * headers closure between the uri and the response, and a RestTemplate response extractor.
 */
@RestController
class OrdersController {

    private final RestClient client
    private final RestTemplate template = new RestTemplate()

    OrdersController(RestClient.Builder builder) {
        this.client = builder.baseUrl('http://orders:8080').build()
    }

    @GetMapping('/orders/{id}')
    String order(@PathVariable('id') Long id) {
        client.get().uri { it.path('/orders/{id}').build(id) }.retrieve().body(String)
    }

    @GetMapping('/orders/{id}/lines')
    String lines(@PathVariable('id') Long id) {
        client.get().uri { UriBuilder builder -> builder.pathSegment('orders', 'lines').queryParam('id', id).build() }
                .retrieve().body(String)
    }

    @GetMapping('/elsewhere')
    String elsewhere(@RequestParam String path) {
        client.get().uri { it.path(path).build() }.retrieve().body(String)
    }

    @GetMapping('/audit')
    String audit() {
        client.post().uri('/audit').headers { it.set('X-Source', 'orders') }.retrieve().body(String)
    }

    @GetMapping('/legacy')
    String legacy() {
        template.execute('http://legacy:8080/stock', HttpMethod.GET, null) { response -> response.body.text }
    }
}
