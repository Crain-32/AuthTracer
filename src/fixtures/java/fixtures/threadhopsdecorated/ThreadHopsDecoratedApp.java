package fixtures.threadhopsdecorated;

import java.util.concurrent.CompletableFuture;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.task.TaskDecorator;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0062: a TaskDecorator carries the SecurityContext to Boot's task executor, but not to CompletableFuture's
 * common pool.
 */
@SpringBootApplication
@EnableMethodSecurity
class ThreadHopsDecoratedApp {

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
}

@Service
class Ledger {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public String total() {
        return "0";
    }
}

@RestController
class LedgerController {

    private final Ledger ledger;

    private final TaskExecutor taskExecutor;

    LedgerController(Ledger ledger, TaskExecutor taskExecutor) {
        this.ledger = ledger;
        this.taskExecutor = taskExecutor;
    }

    @GetMapping("/decorated")
    void decorated() {
        taskExecutor.execute(ledger::total);
    }

    @GetMapping("/common")
    String common() {
        return CompletableFuture.supplyAsync(ledger::total).join();
    }
}
