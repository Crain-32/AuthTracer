package fixtures.threadhopsholderstrategy;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0084: SecurityContextHolder.setContextHolderStrategy(..) with a strategy that keeps the context in an
 * InheritableThreadLocal: a new thread starts with the caller's context.
 */
@SpringBootApplication
@EnableAsync
@EnableMethodSecurity
class ThreadHopsHolderStrategyApp {

    ThreadHopsHolderStrategyApp() {
        SecurityContextHolder.setContextHolderStrategy(new InheritedStrategy());
    }

    @Bean
    ThreadPoolTaskExecutor pool() {
        return new ThreadPoolTaskExecutor();
    }
}

class InheritedStrategy implements SecurityContextHolderStrategy {

    private static final InheritableThreadLocal<SecurityContext> HOLDER = new InheritableThreadLocal<>();

    @Override
    public void clearContext() {
        HOLDER.remove();
    }

    @Override
    public SecurityContext getContext() {
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

    @Async("pool")
    @PreAuthorize("hasRole('ADMIN')")
    public void refresh() {
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

    @PostMapping("/refresh")
    void refresh() {
        reports.refresh();
    }
}
