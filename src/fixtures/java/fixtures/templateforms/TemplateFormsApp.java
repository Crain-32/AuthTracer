package fixtures.templateforms;

import java.net.URI;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * RestTemplate, the other ways requests are written: through its RestOperations interface, with a
 * ParameterizedTypeReference and a request body, as a RequestEntity, with whole URLs in properties, a base held in a
 * local, a host as a URI template variable, and URLs AuthTracer can't read.
 */
record Order(Long id) {
}

record Receipt(Long orderId) {
}

@Component
class OrderCalls {

    private final RestOperations rest;

    @Value("${orders.url}")
    private String ordersUrl;

    @Value("${shipping.url}")
    private String shippingUrl;

    OrderCalls(RestOperations rest) {
        this.rest = rest;
    }

    List<Order> orders() {
        ResponseEntity<List<Order>> response = rest.exchange(ordersUrl, HttpMethod.GET, HttpEntity.EMPTY,
                new ParameterizedTypeReference<List<Order>>() {
                });
        return response.getBody();
    }

    Receipt place(Order order) {
        return rest.postForObject(ordersUrl, order, Receipt.class);
    }

    Receipt ship(Order order) {
        RequestEntity<Order> request = RequestEntity.post(URI.create(shippingUrl + "/shipments")).header("X-Source",
                "orders").body(order);
        return rest.exchange(request, Receipt.class).getBody();
    }

    String shippingStatus() {
        return rest.getForObject(shippingUrl, String.class);
    }

    void cancel(Long id) {
        rest.exchange(RequestEntity.method(HttpMethod.PATCH, "http://orders:8080/orders/{id}/cancel", id).build(),
                Void.class);
    }

    String status(Long id) {
        String base = "http://status:8080";
        return rest.getForObject(base + "/orders/" + id, String.class);
    }

    String track(String gateway, Long id) {
        return rest.getForObject("{gateway}/tracking/{id}", String.class, gateway, id);
    }

    String docs() {
        return rest.getForObject("http://docs:8080/orders?view=full#fields", String.class);
    }

    String anywhere(String url) {
        return rest.getForObject(url, String.class);
    }

    String formatted(Long id) {
        return rest.getForObject(String.format("http://orders:8080/orders/%d", id), String.class);
    }

    String built(Long id) {
        return rest.getForObject(new StringBuilder("http://orders:8080/orders/").append(id).toString(), String.class);
    }

    Receipt resend(RequestEntity<Order> request) {
        return rest.exchange(request, Receipt.class).getBody();
    }
}

/**
 * A template built where it is used, from Boot's builder.
 */
@Component
class WeatherCalls {

    private final RestTemplateBuilder builder;

    WeatherCalls(RestTemplateBuilder builder) {
        this.builder = builder;
    }

    String today() {
        RestTemplate template = builder.rootUri("http://weather:8080").build();
        return template.getForObject("/today", String.class);
    }
}

@ConfigurationProperties("billing")
record BillingProperties(String url) {
}

/**
 * A base URL from a @ConfigurationProperties record, which AuthTracer doesn't read.
 */
@Component
class BillingCalls {

    private final RestTemplate rest = new RestTemplate();

    private final String billingUrl;

    BillingCalls(BillingProperties billing) {
        this.billingUrl = billing.url();
    }

    String invoices() {
        return rest.getForObject(billingUrl + "/invoices", String.class);
    }
}

/**
 * Two templates with different root URIs, each call on its own.
 */
@Component
class RegionCalls {

    private final RestTemplate europe;
    private final RestTemplate america;

    RegionCalls(RestTemplateBuilder builder) {
        this.europe = builder.rootUri("http://eu.regions:8080").build();
        this.america = builder.rootUri("http://us.regions:8080").build();
    }

    String europe() {
        return europe.getForObject("/regions/eu", String.class);
    }

    String america() {
        return america.getForObject("/regions/us", String.class);
    }
}

@RestController
class OrderController {

    private final OrderCalls orders;
    private final RegionCalls regions;

    OrderController(OrderCalls orders, RegionCalls regions) {
        this.orders = orders;
        this.regions = regions;
    }

    @GetMapping("/orders")
    List<Order> orders() {
        return orders.orders();
    }

    @PostMapping("/orders")
    Receipt place(@RequestBody Order order) {
        return orders.place(order);
    }

    @PostMapping("/orders/ship")
    Receipt ship(@RequestBody Order order) {
        return orders.ship(order);
    }

    @GetMapping("/shipping")
    String shipping() {
        return orders.shippingStatus();
    }

    @PostMapping("/orders/{id}/cancel")
    void cancel(@PathVariable Long id) {
        orders.cancel(id);
    }

    @GetMapping("/orders/{id}")
    String status(@PathVariable Long id, @RequestParam String gateway) {
        return orders.status(id) + orders.track(gateway, id) + orders.docs() + regions.europe() + regions.america();
    }

    @GetMapping("/elsewhere")
    String elsewhere(@RequestParam String url, @RequestParam Long id) {
        return orders.anywhere(url) + orders.formatted(id) + orders.built(id)
                + orders.resend(RequestEntity.post(URI.create(url)).body(new Order(id)));
    }
}

@RestController
class SideController {

    private final WeatherCalls weather;
    private final BillingCalls billing;

    SideController(WeatherCalls weather, BillingCalls billing) {
        this.weather = weather;
        this.billing = billing;
    }

    @GetMapping("/weather")
    String weather() {
        return weather.today();
    }

    @GetMapping("/invoices")
    String invoices() {
        return billing.invoices();
    }
}
