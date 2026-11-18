package fixtures.threadhops;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0062: work handed to another thread (an executor, CompletableFuture's common pool, a new Thread) runs
 * without the caller's SecurityContext. Setting the thread-local strategy, the default, carries nothing over.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsApp {

    ThreadHopsApp() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
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

    private final TaskExecutor taskExecutor;

    private final ExecutorService pool = Executors.newFixedThreadPool(2);

    ReportController(Reports reports, TaskExecutor taskExecutor) {
        this.reports = reports;
        this.taskExecutor = taskExecutor;
    }

    @GetMapping("/sync")
    String sync() {
        return reports.build("sync");
    }

    @GetMapping("/supply")
    String supply() {
        return CompletableFuture.supplyAsync(() -> reports.build("supply")).join();
    }

    @GetMapping("/submit")
    Future<String> submit() {
        return pool.submit(() -> reports.build("submit"));
    }

    @PostMapping("/refresh")
    void refresh() {
        taskExecutor.execute(reports::refresh);
    }

    @PostMapping("/thread")
    void thread() {
        new Thread(() -> reports.build("thread")).start();
    }

    @GetMapping("/then")
    String then() {
        return CompletableFuture.completedFuture("then").thenApplyAsync(reports::build).join();
    }

    @GetMapping("/stream")
    List<String> stream() {
        // A sequential stream runs on the caller's thread.
        return List.of("a", "b").stream().map(reports::build).toList();
    }
}
