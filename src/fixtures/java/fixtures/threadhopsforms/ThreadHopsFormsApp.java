package fixtures.threadhopsforms;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0062, the other ways work goes to another thread: CompletableFuture with an executor, virtual threads
 * and thread builders, an executor known by the interfaces it implements, and a task chosen before it is handed
 * over; and a CompletableFuture stage that runs on the caller's thread.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsFormsApp {
}

@Service
class Reports {

    @PreAuthorize("hasRole('ADMIN')")
    public String build(String name) {
        return name;
    }
}

@RestController
class ReportController {

    private final Reports reports;

    private final ExecutorService pool = Executors.newFixedThreadPool(2);

    private final VirtualThreadTaskExecutor virtualExecutor = new VirtualThreadTaskExecutor("reports-");

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @GetMapping("/pooled")
    String pooled() {
        return CompletableFuture.supplyAsync(() -> reports.build("pooled"), pool).join();
    }

    @GetMapping("/applied")
    String applied() {
        // A completed future runs the stage right away, on the caller's thread.
        return CompletableFuture.completedFuture("applied").thenApply(reports::build).join();
    }

    @PostMapping("/virtual")
    void virtual() {
        Thread.startVirtualThread(() -> reports.build("virtual"));
    }

    @PostMapping("/built")
    void built() {
        Thread.ofVirtual().name("report").start(() -> reports.build("built"));
    }

    @PostMapping("/unstarted")
    void unstarted() {
        Thread.ofPlatform().unstarted(() -> reports.build("unstarted")).start();
    }

    @PostMapping("/executor")
    void executor() {
        virtualExecutor.submit(() -> reports.build("executor"));
    }

    @PostMapping("/stored")
    void stored(@RequestParam boolean urgent) {
        Runnable task = urgent ? () -> reports.build("urgent") : () -> reports.build("stored");
        pool.execute(task);
    }
}
