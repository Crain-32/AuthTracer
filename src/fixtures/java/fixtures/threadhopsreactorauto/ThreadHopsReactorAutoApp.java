package fixtures.threadhopsreactorauto;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Decision 0084: with spring.reactor.context-propagation=auto, Reactor restores the thread-local SecurityContext on
 * the scheduler's thread.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsReactorAutoApp {
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
