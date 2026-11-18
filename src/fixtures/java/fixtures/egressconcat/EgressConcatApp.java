package fixtures.egressconcat;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A base URL held in a field initializer, joined with a relative path that has a query string (as
 * spring-petclinic-microservices' VisitsServiceClient does).
 */
record Visits(List<String> items) {
}

class VisitsClient {

    private String hostname = "http://visits-service/";

    private final WebClient.Builder webClientBuilder;

    VisitsClient(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    Visits visits(int petId) {
        return webClientBuilder.build().get().uri(hostname + "pets/visits?petId={petId}", petId).retrieve()
                .bodyToMono(Visits.class).block();
    }
}

@RestController
class OwnerController {

    private final VisitsClient visits;

    OwnerController(VisitsClient visits) {
        this.visits = visits;
    }

    @GetMapping("/owners/{petId}/visits")
    Visits visits(@PathVariable("petId") int petId) {
        return visits.visits(petId);
    }
}
