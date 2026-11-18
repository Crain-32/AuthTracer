package fixtures.webflux;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
class WebFluxController {

    @GetMapping("/staff/list")
    Flux<String> staff() {
        return Flux.just("ann");
    }

    @PostMapping("/orders")
    Mono<String> order() {
        return Mono.just("ok");
    }

    @GetMapping("/orders/{id}")
    Mono<String> read(@PathVariable long id) {
        return Mono.just("order");
    }

    @GetMapping("/legacy/items")
    Mono<String> legacy() {
        return Mono.just("old");
    }

    @GetMapping("/public/info")
    Mono<String> info() {
        return Mono.just("info");
    }

    @GetMapping("/reports/daily")
    Mono<String> report() {
        return Mono.just("report");
    }

    @GetMapping("/partner/data")
    Mono<String> partner() {
        return Mono.just("data");
    }

    @GetMapping("/actuator/health")
    Mono<String> health() {
        return Mono.just("up");
    }

    @GetMapping("/ops/status")
    Mono<String> status() {
        return Mono.just("ok");
    }
}
