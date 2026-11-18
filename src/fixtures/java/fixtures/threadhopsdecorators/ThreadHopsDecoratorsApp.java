package fixtures.threadhopsdecorators;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.task.TaskDecorator;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0062: a TaskDecorator component, which Boot applies to its task executor, carries the SecurityContext.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsDecoratorsApp {
}

@Component
class ContextCopyingDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable task) {
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
    }
}

@Service
class Reports {

    @PreAuthorize("hasRole('ADMIN')")
    public void refresh() {
    }
}

@RestController
class ReportController {

    private final Reports reports;

    private final TaskExecutor taskExecutor;

    ReportController(Reports reports, TaskExecutor taskExecutor) {
        this.reports = reports;
        this.taskExecutor = taskExecutor;
    }

    @PostMapping("/refresh")
    void refresh() {
        taskExecutor.execute(reports::refresh);
    }
}
