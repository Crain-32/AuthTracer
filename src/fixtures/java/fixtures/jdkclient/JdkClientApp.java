package fixtures.jdkclient;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The JDK's HttpClient calling another service.
 */
@RestController
class InventoryController {

    private final HttpClient client = HttpClient.newHttpClient();

    @GetMapping("/stock")
    String stock() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:8090/api/items")).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    @PostMapping("/stock")
    void restock() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create("http://localhost:8090/api/items"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build();
        client.send(request, HttpResponse.BodyHandlers.discarding());
    }
}
