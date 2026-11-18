package fixtures.threadhopsinherited;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0062: the inheritable strategy carries the SecurityContext to the threads a request starts.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsInheritedApp {

    ThreadHopsInheritedApp() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
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

    @PostMapping("/thread")
    void thread() {
        new Thread(() -> reports.build("thread")).start();
    }
}
