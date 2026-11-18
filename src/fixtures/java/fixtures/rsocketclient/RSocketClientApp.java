package fixtures.rsocketclient;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.rsocket.metadata.WellKnownMimeType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Decision 0045: HTTP endpoints that call the rsocket fixture's routes over a requester with fixed credentials.
 */
@SpringBootApplication
class RSocketClientApp {

    @Bean
    RSocketRequester requester(RSocketRequester.Builder builder) {
        return builder.setupMetadata(new UsernamePasswordMetadata("client", "secret"),
                MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString()))
                .tcp("localhost", 7000);
    }
}

record Profile(String name, String email) {
}

record Order(Long id, String sku) {
}

@RestController
class GatewayController {

    private final RSocketRequester requester;

    GatewayController(RSocketRequester requester) {
        this.requester = requester;
    }

    @GetMapping("/profiles/{name}")
    Mono<Profile> profile(@PathVariable String name) {
        return requester.route("profile.{name}", name).retrieveMono(Profile.class);
    }

    @GetMapping("/orders")
    Flux<Order> orders() {
        return requester.route("orders.list").retrieveFlux(Order.class);
    }

    @PostMapping("/audit")
    Mono<Void> audit(@RequestBody String entry) {
        return requester.route("audit").data(entry).send();
    }
}
