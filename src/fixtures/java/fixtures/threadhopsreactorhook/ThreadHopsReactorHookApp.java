package fixtures.threadhopsreactorhook;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Decision 0084: a schedule hook that copies the SecurityContext to every task a scheduler runs.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsReactorHookApp {

    ThreadHopsReactorHookApp() {
        Schedulers.onScheduleHook("security", task -> {
            SecurityContext context = SecurityContextHolder.getContext();
            return () -> {
                SecurityContextHolder.setContext(context);
                try {
                    task.run();
                }
                finally {
                    SecurityContextHolder.clearContext();
                }
            };
        });
    }
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

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @GetMapping("/blocked")
    String blocked() {
        return Mono.fromCallable(() -> reports.build("blocked")).subscribeOn(Schedulers.boundedElastic()).block();
    }
}
