package fixtures.threadhopswaited;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0084: a caller that waits for work it handed to another thread (get(), join(), or returning the future to
 * Spring MVC) fails with it; one that goes on, catches the failure or recovers from it doesn't.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsWaitedApp {
}

@Service
class Reports {

    @PreAuthorize("hasRole('ADMIN')")
    public String build(String name) {
        return name;
    }
}

@Service
class Loader {

    private final Reports reports;

    Loader(Reports reports) {
        this.reports = reports;
    }

    CompletableFuture<String> load(String name) {
        return CompletableFuture.supplyAsync(() -> reports.build(name));
    }
}

@RestController
class ReportController {

    private final Reports reports;
    private final Loader loader;
    private final ExecutorService pool = Executors.newFixedThreadPool(2);

    ReportController(Reports reports, Loader loader) {
        this.reports = reports;
        this.loader = loader;
    }

    @GetMapping("/loaded")
    String loaded() {
        // The future comes back from the service that started it.
        return loader.load("loaded").join();
    }

    @GetMapping("/passed")
    CompletableFuture<String> passed() {
        return loader.load("passed");
    }

    @PostMapping("/started")
    void started() {
        loader.load("started");
    }

    @GetMapping("/joined")
    String joined() {
        return CompletableFuture.supplyAsync(() -> reports.build("joined")).join();
    }

    @GetMapping("/returned")
    CompletableFuture<String> returned() {
        return CompletableFuture.supplyAsync(() -> reports.build("returned"));
    }

    @GetMapping("/got")
    String got() throws Exception {
        Future<String> report = pool.submit(() -> reports.build("got"));
        return report.get();
    }

    @GetMapping("/chained")
    String chained() {
        return CompletableFuture.supplyAsync(() -> reports.build("chained")).thenApply(String::trim).join();
    }

    @GetMapping("/all")
    String all() {
        CompletableFuture<String> daily = CompletableFuture.supplyAsync(() -> reports.build("daily"));
        CompletableFuture<String> weekly = CompletableFuture.supplyAsync(() -> reports.build("weekly"));
        CompletableFuture.allOf(daily, weekly).join();
        return "done";
    }

    @GetMapping("/caught")
    String caught() {
        Future<String> report = pool.submit(() -> reports.build("caught"));
        try {
            return report.get();
        }
        catch (InterruptedException | ExecutionException e) {
            return "fallback";
        }
    }

    @GetMapping("/recovered")
    String recovered() {
        return CompletableFuture.supplyAsync(() -> reports.build("recovered")).exceptionally(e -> "fallback").join();
    }

    @PostMapping("/submitted")
    void submitted() {
        pool.submit(() -> reports.build("submitted"));
    }
}
