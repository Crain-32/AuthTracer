package fixtures.asyncexecutors;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.task.ThreadPoolTaskExecutorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0084: {@code @Async("name")} runs on that executor bean, which carries the SecurityContext when it is
 * Spring Security's delegating executor or has a decorator that copies it, and not when its decorator copies
 * something else.
 */
@SpringBootApplication
@EnableAsync
@EnableMethodSecurity
class AsyncExecutorsApp {

    @Bean
    ThreadPoolTaskExecutor plain() {
        return new ThreadPoolTaskExecutor();
    }

    @Bean
    Executor secured() {
        return new DelegatingSecurityContextAsyncTaskExecutor(new ThreadPoolTaskExecutor());
    }

    @Bean
    ThreadPoolTaskExecutor traced() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setTaskDecorator(new TraceIdDecorator());
        return executor;
    }

    @Bean("reporting")
    ThreadPoolTaskExecutor reportingExecutor() {
        return new ThreadPoolTaskExecutor();
    }

    @Bean
    @Qualifier("audited")
    DelegatingSecurityContextAsyncTaskExecutor auditExecutor() {
        return new DelegatingSecurityContextAsyncTaskExecutor(new ThreadPoolTaskExecutor());
    }

    @Bean
    ThreadPoolTaskExecutor built(ThreadPoolTaskExecutorBuilder builder) {
        // Its own decorator, not the application's.
        return builder.taskDecorator(new TraceIdDecorator()).build();
    }

    @Bean
    ThreadPoolTaskExecutor given(TaskDecorator decorator) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setTaskDecorator(decorator);
        return executor;
    }

    @Bean
    ThreadPoolTaskExecutor copying() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setTaskDecorator(task -> {
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
        return executor;
    }
}

final class TraceIds {

    static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TraceIds() {
    }
}

/**
 * Copies the trace id, not the SecurityContext.
 */
class TraceIdDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable task) {
        String traceId = TraceIds.CURRENT.get();
        return () -> {
            TraceIds.CURRENT.set(traceId);
            task.run();
        };
    }
}

@Service
class Reports {

    @Async("plain")
    @PreAuthorize("hasRole('ADMIN')")
    public void plain() {
    }

    @Async("secured")
    @PreAuthorize("hasRole('ADMIN')")
    public void secured() {
    }

    @Async("traced")
    @PreAuthorize("hasRole('ADMIN')")
    public void traced() {
    }

    @Async("copying")
    @PreAuthorize("hasRole('ADMIN')")
    public void copying() {
    }

    @Async("${app.reports-executor}")
    @PreAuthorize("hasRole('ADMIN')")
    public void configured() {
    }

    @Async("reporting")
    @PreAuthorize("hasRole('ADMIN')")
    public void reporting() {
    }

    @Async("audited")
    @PreAuthorize("hasRole('ADMIN')")
    public void audited() {
    }

    @Async("built")
    @PreAuthorize("hasRole('ADMIN')")
    public void built() {
    }

    @Async("given")
    @PreAuthorize("hasRole('ADMIN')")
    public void given() {
    }

    @Async("plain")
    @PreAuthorize("hasRole('ADMIN')")
    public CompletableFuture<String> build() {
        return CompletableFuture.completedFuture("report");
    }
}

@RestController
class ReportController {

    private final Reports reports;

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @PostMapping("/plain")
    void plain() {
        reports.plain();
    }

    @PostMapping("/secured")
    void secured() {
        reports.secured();
    }

    @PostMapping("/traced")
    void traced() {
        reports.traced();
    }

    @PostMapping("/copying")
    void copying() {
        reports.copying();
    }

    @PostMapping("/configured")
    void configured() {
        reports.configured();
    }

    @PostMapping("/reporting")
    void reporting() {
        reports.reporting();
    }

    @PostMapping("/audited")
    void audited() {
        reports.audited();
    }

    @PostMapping("/builder")
    void builder() {
        reports.built();
    }

    @PostMapping("/given")
    void given() {
        reports.given();
    }

    @GetMapping("/built")
    String built() {
        return reports.build().join();
    }

    @GetMapping("/handed")
    CompletableFuture<String> handed() {
        return reports.build();
    }
}
