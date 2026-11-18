package fixtures.rsocketclientforms;

import java.net.URI;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.security.rsocket.metadata.BearerTokenAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.BearerTokenMetadata;
import org.springframework.stereotype.Component;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.rsocket.metadata.WellKnownMimeType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * RSocket requesters, the other ways they are built and used: over a WebSocket with a bearer token, over TCP with
 * the host or port from properties, two requests prepared together, and a route AuthTracer can't read.
 */
record Quote(String symbol, double price) {
}

@Component
class QuoteClient {

    private final RSocketRequester requester;

    QuoteClient(RSocketRequester.Builder builder, @Value("${quotes.token}") String token) {
        this.requester = builder
                .rsocketStrategies(strategies -> strategies.encoder(new BearerTokenAuthenticationEncoder()))
                .setupMetadata(new BearerTokenMetadata(token),
                        MimeTypeUtils.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString()))
                .websocket(URI.create("ws://quotes:7001/rsocket"));
    }

    Mono<Quote> quote(String symbol) {
        return requester.route("quote.{symbol}", symbol).retrieveMono(Quote.class);
    }

    Flux<Quote> ticks() {
        return requester.route("quotes.ticks").retrieveFlux(Quote.class);
    }

    Mono<Quote> any(String route) {
        return requester.route(route).retrieveMono(Quote.class);
    }

    void close() {
        requester.dispose();
    }
}

@Component
class FeedClient {

    private final RSocketRequester requester;

    FeedClient(RSocketRequester.Builder builder, @Value("${feed.host}") String host) {
        this.requester = builder.tcp(host, 7002);
    }

    Mono<String> both() {
        RSocketRequester.RequestSpec first = requester.route("feed.first");
        RSocketRequester.RequestSpec second = requester.route("feed.second");
        return first.retrieveMono(String.class).zipWith(second.retrieveMono(String.class), String::concat);
    }
}

@Component
class AlertClient {

    private final RSocketRequester requester;

    AlertClient(RSocketRequester.Builder builder, @Value("${alerts.port}") int port) {
        this.requester = builder.tcp("alerts", port);
    }

    Mono<Void> raise(String alert) {
        return requester.route("alerts.raise").data(alert).send();
    }
}

@RestController
class QuoteController {

    private final QuoteClient quotes;
    private final FeedClient feed;
    private final AlertClient alerts;

    QuoteController(QuoteClient quotes, FeedClient feed, AlertClient alerts) {
        this.quotes = quotes;
        this.feed = feed;
        this.alerts = alerts;
    }

    @GetMapping("/quotes/{symbol}")
    Mono<Quote> quote(@PathVariable String symbol) {
        return quotes.quote(symbol);
    }

    @GetMapping("/quotes")
    Flux<Quote> ticks() {
        return quotes.ticks();
    }

    @GetMapping("/routes")
    Mono<Quote> any(@RequestParam String route) {
        quotes.close();
        return quotes.any(route);
    }

    @GetMapping("/feed")
    Mono<String> feed() {
        return feed.both();
    }

    @PostMapping("/alerts")
    Mono<Void> raise(@RequestBody String alert) {
        return alerts.raise(alert);
    }
}
