package fixtures.threadhopsreactor;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Decision 0084: a servlet application's Reactor pipelines. Work a scheduler runs (subscribeOn, and what comes after
 * publishOn) has no thread-local SecurityContext; a caller that blocks on the pipeline, or returns it to Spring, gets
 * its failure, one that subscribes and goes on, or recovers from errors, doesn't.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsReactorApp {

    ThreadHopsReactorApp() {
        // A schedule hook that times the work: it doesn't carry the SecurityContext.
        Schedulers.onScheduleHook("timing", task -> () -> {
            long start = System.nanoTime();
            task.run();
            Timings.record(System.nanoTime() - start);
        });
    }
}

final class Timings {

    private Timings() {
    }

    static void record(long nanos) {
    }
}

@Service
class Reports {

    @PreAuthorize("hasRole('ADMIN')")
    public String build(String name) {
        return name;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void refresh() {
    }
}

@RestController
class ReportController {

    private final Reports reports;

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @GetMapping("/blocked")
    String blocked() {
        return Mono.fromCallable(() -> reports.build("blocked")).subscribeOn(Schedulers.boundedElastic()).block();
    }

    @GetMapping("/returned")
    Mono<String> returned() {
        return Mono.fromCallable(() -> reports.build("returned")).subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping("/fired")
    void fired() {
        Mono.fromRunnable(reports::refresh).subscribeOn(Schedulers.parallel()).subscribe();
    }

    @GetMapping("/published")
    Flux<String> published() {
        return Flux.just("a", "b").publishOn(Schedulers.parallel()).map(reports::build);
    }

    @GetMapping("/recovered")
    String recovered() {
        return Mono.fromCallable(() -> reports.build("recovered")).subscribeOn(Schedulers.boundedElastic())
                .onErrorReturn("fallback").block();
    }

    @GetMapping("/before")
    Flux<String> before() {
        // Mapped on the caller's thread, then handed on.
        return Flux.just("a").map(reports::build).publishOn(Schedulers.parallel());
    }

    @GetMapping("/zipped")
    String zipped() {
        Mono<String> daily = Mono.fromCallable(() -> reports.build("daily")).subscribeOn(Schedulers.boundedElastic());
        Mono<String> weekly = Mono.just("weekly");
        return Mono.zip(daily, weekly).map(both -> both.getT1() + both.getT2()).block();
    }

    @GetMapping("/immediate")
    String immediate() {
        return Mono.fromCallable(() -> reports.build("immediate")).subscribeOn(Schedulers.immediate()).block();
    }
}
