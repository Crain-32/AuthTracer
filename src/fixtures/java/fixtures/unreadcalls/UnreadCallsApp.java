package fixtures.unreadcalls;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.graphql.client.HttpSyncGraphQlClient;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriBuilder;
import org.springframework.ws.client.core.WebServiceTemplate;

import jakarta.jms.Destination;

/**
 * Decision 0082: calls AuthTracer recognises but whose URL, route, topic or operation it can't read, each still an
 * Egress: URLs from parameters, uri functions that add a path from a parameter or change the host, a template's
 * own function, request entities and requests from parameters, a route, a document, a SOAP request, topics and
 * destinations from parameters, a record, a named exchange, a binding from a parameter.
 */
@SpringBootApplication
class UnreadCallsApp {
}

@Component
class OrderCalls {

    private final RestClient client = RestClient.create("http://orders:8080");

    private final WebClient web = WebClient.create("http://orders:8080");

    private final RestTemplate rest = new RestTemplate();

    String anywhere(String url) {
        return client.get().uri(url).retrieve().body(String.class);
    }

    String pathFromParameter(String path) {
        return client.post().uri(builder -> builder.path(path).build()).retrieve().body(String.class);
    }

    String otherHost(String host) {
        return client.get().uri(builder -> builder.host(host).path("/orders").build()).retrieve().body(String.class);
    }

    String templateFunction(String path) {
        return client.get().uri("/orders/{id}", builder -> builder.path(path).build(7)).retrieve()
                .body(String.class);
    }

    String replaced() {
        return client.get().uri(builder -> builder.replacePath("/v2/orders").build()).retrieve().body(String.class);
    }

    String helped(long id) {
        return client.get().uri(builder -> withId(builder, id)).retrieve().body(String.class);
    }

    private static URI withId(UriBuilder builder, long id) {
        return builder.path("/orders/{id}").build(id);
    }

    String templateQuery() {
        return client.get().uri("/orders", builder -> builder.queryParam("page", 2).build()).retrieve()
                .body(String.class);
    }

    String templateFunctionWithConstants() {
        return client.get().uri("/orders", builder -> builder.path("/{id}/lines").build(7)).retrieve()
                .body(String.class);
    }

    String webAnywhere(URI uri) {
        return web.delete().uri(uri).retrieve().bodyToMono(String.class).block();
    }

    String templateAnywhere(String url) {
        return rest.getForObject(url, String.class);
    }

    void templateExchange(String url) {
        rest.exchange(url, HttpMethod.PUT, null, Void.class);
    }

    String entity(RequestEntity<?> request) {
        return rest.exchange(request, String.class).getBody();
    }

    String jdk(HttpClient http, HttpRequest request) throws Exception {
        return http.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    String jdkBuilder(HttpClient http, HttpRequest.Builder builder) throws Exception {
        http.send(builder.uri(URI.create("http://orders:8080/orders")).build(), HttpResponse.BodyHandlers.ofString());
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofString()).body();
    }

    String attribute(Map<String, Object> attributes) {
        return rest.getForObject((String) attributes.get("url"), String.class);
    }
}

@Component
class OtherCalls {

    private final RSocketRequester requester;

    private final HttpSyncGraphQlClient graphQl = HttpSyncGraphQlClient.create(
            RestClient.create("http://people:8095/graphql"));

    private final WebServiceTemplate soap = new WebServiceTemplate();

    OtherCalls(RSocketRequester.Builder builder) {
        this.requester = builder.tcp("quotes", 7001);
    }

    String route(String route) {
        return requester.route(route).retrieveMono(String.class).block();
    }

    String document(String document, String path) {
        return graphQl.document(document).retrieveSync(path).toEntity(String.class);
    }

    Object soap(Object request) {
        return soap.marshalSendAndReceive("http://countries:8080/ws", request);
    }

    boolean written() {
        return soap.sendAndReceive("http://countries:8080/ws", message -> {
        }, message -> {
        });
    }
}

@Component
class Sends {

    private final KafkaTemplate<String, String> kafka;
    private final JmsTemplate jms;
    private final RabbitTemplate rabbit;
    private final StreamBridge bridge;

    Sends(KafkaTemplate<String, String> kafka, JmsTemplate jms, RabbitTemplate rabbit, StreamBridge bridge) {
        this.kafka = kafka;
        this.jms = jms;
        this.rabbit = rabbit;
        this.bridge = bridge;
    }

    void send(String topic, Destination destination, String exchange, String binding, String body) {
        kafka.send(topic, body);
        kafka.send(new ProducerRecord<>(topic, body));
        jms.convertAndSend(destination, body);
        rabbit.convertAndSend(exchange, "orders.created", body);
        bridge.send(binding, body);
    }
}

@RestController
class UnreadController {

    private final OrderCalls orders;
    private final OtherCalls others;
    private final Sends sends;

    UnreadController(OrderCalls orders, OtherCalls others, Sends sends) {
        this.orders = orders;
        this.others = others;
        this.sends = sends;
    }

    @GetMapping("/orders")
    String orders(@RequestParam String url, @RequestParam String path) throws Exception {
        return orders.anywhere(url) + orders.pathFromParameter(path) + orders.otherHost(url)
                + orders.templateFunction(path) + orders.templateFunctionWithConstants() + orders.templateQuery()
                + orders.replaced() + orders.helped(7)
                + orders.webAnywhere(URI.create(url)) + orders.templateAnywhere(url)
                + orders.entity(RequestEntity.get(url).build()) + orders.jdk(HttpClient.newHttpClient(),
                        HttpRequest.newBuilder(URI.create(url)).build());
    }

    @GetMapping("/put")
    void put(@RequestParam String url) throws Exception {
        orders.templateExchange(url);
        orders.jdkBuilder(HttpClient.newHttpClient(), HttpRequest.newBuilder().PUT(BodyPublishers.noBody()));
        orders.attribute(Map.of("url", url));
    }

    @GetMapping("/others")
    String others(@RequestParam String route, @RequestParam String document) {
        return others.route(route) + others.document(document, route) + others.soap(document) + others.written();
    }

    @GetMapping("/sends")
    void sends(@RequestParam String topic, @RequestParam String binding) {
        sends.send(topic, null, topic, binding, "body");
    }
}
