package fixtures.threadhopspooled;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0084, amended: the inheritable strategy gives a pool's thread the SecurityContext of the request that
 * created it, and the thread keeps it for every task after; a thread started for each task gets the caller's.
 */
@SpringBootApplication
@EnableMethodSecurity
@EnableAsync
class ThreadHopsPooledApp {

    ThreadHopsPooledApp() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    @Bean
    ThreadPoolTaskExecutor reportsExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(4);
        return executor;
    }

    @Bean
    SimpleAsyncTaskExecutor perTaskExecutor() {
        return new SimpleAsyncTaskExecutor("export-");
    }
}

@Service
class Reports {

    @PreAuthorize("hasRole('ADMIN')")
    public String build(String name) {
        return name;
    }
}

@Service
class Exports {

    @Async
    @PreAuthorize("hasRole('ADMIN')")
    public void unnamed() {
    }

    @Async("reportsExecutor")
    @PreAuthorize("hasRole('ADMIN')")
    public void pooled() {
    }

    @Async("perTaskExecutor")
    @PreAuthorize("hasRole('ADMIN')")
    public void perTask() {
    }
}

@RestController
class ReportController {

    private final Reports reports;
    private final Exports exports;
    private final ExecutorService pool = Executors.newFixedThreadPool(4);
    private final SimpleAsyncTaskExecutor simple = new SimpleAsyncTaskExecutor();

    ReportController(Reports reports, Exports exports) {
        this.reports = reports;
        this.exports = exports;
    }

    @PostMapping("/submit")
    void submit() {
        pool.submit(() -> reports.build("submit"));
    }

    @GetMapping("/supply")
    String supply() {
        return CompletableFuture.supplyAsync(() -> reports.build("supply")).join();
    }

    @PostMapping("/simple")
    void simple() {
        simple.execute(() -> reports.build("simple"));
    }

    @PostMapping("/thread")
    void thread() {
        new Thread(() -> reports.build("thread")).start();
    }

    @PostMapping("/unnamed")
    void unnamed() {
        exports.unnamed();
    }

    @PostMapping("/pooled")
    void pooled() {
        exports.pooled();
    }

    @PostMapping("/per-task")
    void perTask() {
        exports.perTask();
    }
}
