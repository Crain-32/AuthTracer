package fixtures.fluentforms;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * RestClient and WebClient, the other ways requests are written: a request body before the response's, two
 * requests in one method, a request spec a helper builds, a method given as an HttpMethod, a client built inline or
 * picked by a method, a query on the base URL, a host in the URL, a UriComponentsBuilder from scratch, and URLs
 * AuthTracer can't read.
 */
record Order(Long id) {
}

record Receipt(Long orderId) {
}

@Component
class OrderClient {

    private final RestClient client = RestClient.builder().baseUrl("http://orders:8080").build();

    private final Map<String, RestClient> regions = Map.of("eu", RestClient.create("http://eu.orders:8080"));

    Receipt place(Order order) {
        return client.post().uri("/orders").body(order).retrieve().body(Receipt.class);
    }

    Receipt placeAll(List<Order> orders) {
        return client.post().uri("/orders/batch").body(orders, new ParameterizedTypeReference<List<Order>>() {
        }).retrieve().body(Receipt.class);
    }

    Order refresh(Long id) {
        client.post().uri("/orders/{id}/refresh", id).retrieve().toBodilessEntity();
        return client.get().uri("/orders/{id}", id).retrieve().body(Order.class);
    }

    Order archived(Long id) {
        return request(id).retrieve().body(Order.class);
    }

    private RestClient.RequestHeadersSpec<?> request(Long id) {
        return client.get().uri("/archive/{id}", id);
    }

    void touch(Long id) {
        client.method(HttpMethod.PATCH).uri("/orders/{id}/touch", id).retrieve().toBodilessEntity();
        client.method(HttpMethod.OPTIONS).retrieve().toBodilessEntity();
    }

    List<Order> page(int page) {
        return client.get().uri(builder -> builder.queryParam("page", page).build()).retrieve()
                .body(new ParameterizedTypeReference<List<Order>>() {
                });
    }

    String health() {
        return RestClient.create("http://health:8080").get().uri("/health").retrieve().body(String.class);
    }

    String regional(String region, Long id) {
        return regions.get(region).get().uri("/orders/{id}", id).retrieve().body(String.class);
    }

    String anywhere(String url, String path) {
        return client.get().uri(url).retrieve().body(String.class)
                + client.get().uri(builder -> builder.path(path).build()).retrieve().body(String.class)
                + client.get().uri(builder -> builder.pathSegment("orders", path).build()).retrieve()
                        .body(String.class);
    }
}

@Component
class ReportClient {

    private final WebClient client = WebClient.create();

    @Value("${reports.host}")
    private String host;

    String report(Long id) {
        return client.get().uri("http://" + host + "/reports/" + id).retrieve().bodyToMono(String.class).block();
    }

    String summary() {
        return client.get().uri(UriComponentsBuilder.newInstance().path("/reports").path("summary").build().toUri())
                .retrieve().bodyToMono(String.class).block();
    }

    List<String> stream() {
        return client.get().uri("http://reports:8080/reports/stream").retrieve().toEntityFlux(String.class)
                .block().getBody().collectList().block();
    }
}

@RestController
class OrderController {

    private final OrderClient orders;
    private final ReportClient reports;

    OrderController(OrderClient orders, ReportClient reports) {
        this.orders = orders;
        this.reports = reports;
    }

    @PostMapping("/orders")
    Receipt place(@RequestBody Order order) {
        return orders.place(order);
    }

    @PostMapping("/orders/batch")
    Receipt placeAll(@RequestBody List<Order> batch) {
        return orders.placeAll(batch);
    }

    @PostMapping("/orders/{id}/refresh")
    Order refresh(@PathVariable Long id) {
        return orders.refresh(id);
    }

    @GetMapping("/archive/{id}")
    Order archived(@PathVariable Long id) {
        return orders.archived(id);
    }

    @PostMapping("/orders/{id}/touch")
    void touch(@PathVariable Long id) {
        orders.touch(id);
    }

    @GetMapping("/orders")
    List<Order> page(@RequestParam int page) {
        return orders.page(page);
    }

    @GetMapping("/status")
    String status(@RequestParam String region, @RequestParam Long id) {
        return orders.health() + orders.regional(region, id);
    }

    @GetMapping("/elsewhere")
    String elsewhere(@RequestParam String url, @RequestParam String path) {
        return orders.anywhere(url, path);
    }

    @GetMapping("/reports/{id}")
    String report(@PathVariable Long id) {
        return reports.report(id) + reports.summary() + reports.stream();
    }
}
