package fixtures.threadhopswaitedforms;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Decision 0099: the other ways a caller waits for work it handed to another thread: futures kept in a collection or
 * a field, waits in a lambda, and Reactor pipelines a scheduler runs from another method.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsWaitedFormsApp {
}

@Service
class Reports {

    @PreAuthorize("hasRole('ADMIN')")
    public String build(String name) {
        return name;
    }
}

@Service
class Batch {

    private final Reports reports;
    private CompletableFuture<String> pending;
    private final List<CompletableFuture<String>> queue = new ArrayList<>();

    Batch(Reports reports) {
        this.reports = reports;
    }

    void start(String name) {
        pending = CompletableFuture.supplyAsync(() -> reports.build(name));
    }

    String await() {
        return pending.join();
    }

    void enqueue(String name) {
        queue.add(CompletableFuture.supplyAsync(() -> reports.build(name)));
    }

    void drain() {
        queue.forEach(CompletableFuture::join);
    }
}

@Service
class Pipelines {

    private final Reports reports;

    Pipelines(Reports reports) {
        this.reports = reports;
    }

    Mono<String> load(String name) {
        return Mono.fromCallable(() -> reports.build(name));
    }

    Mono<String> scheduled(String name) {
        return Mono.fromCallable(() -> name).subscribeOn(Schedulers.boundedElastic());
    }

    static <T> Mono<T> offloaded(Mono<T> work) {
        return work.subscribeOn(Schedulers.parallel());
    }

    static Mono<String> traced(Mono<String> work) {
        return work.map(String::trim);
    }
}

@RestController
class ReportController {

    private final Reports reports;
    private final Batch batch;
    private final Pipelines pipelines;
    private CompletableFuture<String> latest;

    ReportController(Reports reports, Batch batch, Pipelines pipelines) {
        this.reports = reports;
        this.batch = batch;
        this.pipelines = pipelines;
    }

    @GetMapping("/collected")
    String collected() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        futures.add(CompletableFuture.supplyAsync(() -> reports.build("daily")));
        StringBuilder all = new StringBuilder();
        for (CompletableFuture<String> future : futures) {
            all.append(future.join());
        }
        return all.toString();
    }

    @GetMapping("/streamed")
    List<String> streamed() {
        List<CompletableFuture<String>> futures = List.of(CompletableFuture.supplyAsync(() -> reports.build("a")),
                CompletableFuture.supplyAsync(() -> reports.build("b")));
        return futures.stream().map(CompletableFuture::join).toList();
    }

    @GetMapping("/each")
    String each() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        futures.add(CompletableFuture.supplyAsync(() -> reports.build("each")));
        futures.forEach(future -> record(future.join()));
        return "done";
    }

    @GetMapping("/captured")
    String captured() {
        CompletableFuture<String> report = CompletableFuture.supplyAsync(() -> reports.build("captured"));
        String suffix = "!";
        return Optional.of("ready").map(ready -> report.join() + suffix).orElse("none");
    }

    @GetMapping("/fallback")
    String fallback() {
        CompletableFuture<String> report = CompletableFuture.supplyAsync(() -> reports.build("fallback"));
        return Optional.<String>empty().orElseGet(report::join);
    }

    @GetMapping("/kept")
    String kept() {
        latest = CompletableFuture.supplyAsync(() -> reports.build("kept"));
        return latest.join();
    }

    @GetMapping("/batched")
    String batched() {
        batch.start("batched");
        return batch.await();
    }

    @GetMapping("/drained")
    String drained() {
        batch.enqueue("drained");
        batch.drain();
        return "done";
    }

    @PostMapping("/queued")
    void queued() {
        // What it calls next doesn't wait on the future start keeps.
        batch.start("queued");
        batch.enqueue("queued");
    }

    @PostMapping("/forgotten")
    void forgotten() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        futures.add(CompletableFuture.supplyAsync(() -> reports.build("forgotten")));
        // Neither lambda waits on them.
        futures.forEach(future -> record("queued"));
        List.of("forgotten").forEach(name -> record(name));
    }

    @PostMapping("/dropped")
    void dropped() {
        // Subscribed where it is: on the caller's thread.
        pipelines.load("dropped").subscribe();
    }

    @PostMapping("/elsewhere")
    void elsewhere() {
        // The lambda that waits runs on another thread, not the caller's.
        CompletableFuture<String> report = CompletableFuture.supplyAsync(() -> reports.build("elsewhere"));
        CompletableFuture.runAsync(() -> report.join());
    }

    @GetMapping("/offloaded")
    String offloaded() {
        return pipelines.load("offloaded").map(String::trim).subscribeOn(Schedulers.boundedElastic()).block();
    }

    @GetMapping("/mapped")
    String mapped() {
        return pipelines.scheduled("mapped").map(name -> reports.build(name)).block();
    }

    @GetMapping("/handed")
    String handed() {
        return Pipelines.offloaded(Mono.fromCallable(() -> reports.build("handed"))).block();
    }

    @GetMapping("/inline")
    String inline() {
        // Nothing schedules it: it runs where it is blocked on.
        return Pipelines.traced(pipelines.load("inline")).block();
    }

    private void record(String report) {
    }
}
