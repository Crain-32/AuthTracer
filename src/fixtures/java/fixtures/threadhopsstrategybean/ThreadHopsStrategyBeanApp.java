package fixtures.threadhopsstrategybean;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0084: a SecurityContextHolderStrategy bean, which Spring Security's method interceptors use, that keeps the
 * context in a plain ThreadLocal: a new thread starts without it.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsStrategyBeanApp {

    @Bean
    SecurityContextHolderStrategy securityContextHolderStrategy() {
        return new CountingStrategy();
    }
}

class CountingStrategy implements SecurityContextHolderStrategy {

    private static final ThreadLocal<SecurityContext> HOLDER = new ThreadLocal<>();

    private int reads;

    @Override
    public void clearContext() {
        HOLDER.remove();
    }

    @Override
    public SecurityContext getContext() {
        reads++;
        SecurityContext context = HOLDER.get();
        if (context == null) {
            context = createEmptyContext();
            HOLDER.set(context);
        }
        return context;
    }

    @Override
    public void setContext(SecurityContext context) {
        HOLDER.set(context);
    }

    @Override
    public SecurityContext createEmptyContext() {
        return new SecurityContextImpl();
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
