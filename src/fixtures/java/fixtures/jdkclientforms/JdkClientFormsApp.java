package fixtures.jdkclientforms;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The JDK's HttpClient, the other ways requests are written: sent asynchronously, with no method (GET), with
 * method(..) given a constant or not, a base URL from a property, and requests AuthTracer can't read.
 */
@Component
class ShipmentClient {

    private final HttpClient client = HttpClient.newHttpClient();

    @Value("${tracking.url}")
    private String trackingUrl;

    CompletableFuture<String> track(String id) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(trackingUrl + "/shipments/" + id)).build();
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(HttpResponse::body);
    }

    void reroute(String id, String route) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create("http://shipping:8080/shipments/" + id))
                .method("PATCH", HttpRequest.BodyPublishers.ofString(route)).build();
        client.send(request, HttpResponse.BodyHandlers.discarding());
    }

    void forward(String verb, String id) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://shipping:8080/forwarded/" + id))
                .method(verb, HttpRequest.BodyPublishers.noBody()).build();
        client.send(request, HttpResponse.BodyHandlers.discarding());
    }

    String relay(HttpRequest request) throws IOException, InterruptedException {
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    String anywhere(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    String version() {
        return client.version().name();
    }
}

@RestController
class ShipmentController {

    private final ShipmentClient shipments;

    ShipmentController(ShipmentClient shipments) {
        this.shipments = shipments;
    }

    @GetMapping("/shipments/{id}")
    CompletableFuture<String> track(@PathVariable String id) {
        return shipments.track(id);
    }

    @PostMapping("/shipments/{id}/route")
    void reroute(@PathVariable String id, @RequestBody String route) throws IOException, InterruptedException {
        shipments.reroute(id, route);
    }

    @PostMapping("/shipments/{id}/forward")
    void forward(@PathVariable String id, @RequestParam String verb) throws IOException, InterruptedException {
        shipments.forward(verb, id);
    }

    @GetMapping("/elsewhere")
    String elsewhere(@RequestParam String url) throws IOException, InterruptedException {
        return shipments.anywhere(url) + shipments.relay(HttpRequest.newBuilder(URI.create(url)).build())
                + shipments.version();
    }
}
