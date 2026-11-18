package fixtures.asyncexecutorsdecorated;

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
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0084: the application's TaskDecorator bean copies the SecurityContext. Boot's builder applies it, and so
 * does a bean method it is handed to; an executor created without it doesn't have it.
 */
@SpringBootApplication
@EnableAsync
@EnableMethodSecurity
class AsyncExecutorsDecoratedApp {

    @Bean
    TaskDecorator securityContextDecorator() {
        return task -> {
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
        };
    }

    @Bean
    ThreadPoolTaskExecutor pooled(ThreadPoolTaskExecutorBuilder builder) {
        return builder.corePoolSize(4).build();
    }

    @Bean
    ThreadPoolTaskExecutor given(TaskDecorator decorator) {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setTaskDecorator(decorator);
        return executor;
    }

    @Bean
    ThreadPoolTaskExecutor plain() {
        return new ThreadPoolTaskExecutor();
    }
}

@Service
class Reports {

    @Async("pooled")
    @PreAuthorize("hasRole('ADMIN')")
    public void pooled() {
    }

    @Async("given")
    @PreAuthorize("hasRole('ADMIN')")
    public void given() {
    }

    @Async("plain")
    @PreAuthorize("hasRole('ADMIN')")
    public void plain() {
    }

    @Async("applicationTaskExecutor")
    @PreAuthorize("hasRole('ADMIN')")
    public void elsewhere() {
    }
}

@RestController
class ReportController {

    private final Reports reports;

    ReportController(Reports reports) {
        this.reports = reports;
    }

    @PostMapping("/pooled")
    void pooled() {
        reports.pooled();
    }

    @PostMapping("/given")
    void given() {
        reports.given();
    }

    @PostMapping("/plain")
    void plain() {
        reports.plain();
    }

    @PostMapping("/elsewhere")
    void elsewhere() {
        reports.elsewhere();
    }
}
