package fixtures.threadhopsdelegating;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0062: an executor Spring Security wraps carries the SecurityContext to its threads, also when a
 * CompletableFuture runs on it.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsDelegatingApp {
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

    private final DelegatingSecurityContextExecutorService executor = new DelegatingSecurityContextExecutorService(
            Executors.newFixedThreadPool(2));

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @GetMapping("/submitted")
    Future<String> submitted() {
        return executor.submit(() -> reports.build("submitted"));
    }

    @GetMapping("/pooled")
    String pooled() {
        return CompletableFuture.supplyAsync(() -> reports.build("pooled"), executor).join();
    }
}
