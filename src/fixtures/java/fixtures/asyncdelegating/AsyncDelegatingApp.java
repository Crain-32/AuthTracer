package fixtures.asyncdelegating;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0048: the @Async executor is Spring Security's delegating one, declared as a bean of its type, so @Async
 * methods keep the caller's SecurityContext.
 */
@SpringBootApplication
@EnableAsync
@EnableMethodSecurity
class AsyncDelegatingApp {

    @Bean
    DelegatingSecurityContextAsyncTaskExecutor taskExecutor(ThreadPoolTaskExecutor delegate) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }
}

@Service
class Audit {

    @PreAuthorize("hasRole('AUDITOR')")
    public void record(String entry) {
    }
}

@Service
class Notifier {

    private final Audit audit;

    Notifier(Audit audit) {
        this.audit = audit;
    }

    @Async
    public void notifyAuditors() {
        audit.record("notified");
    }
}

@RestController
class NotificationController {

    private final Notifier notifier;

    NotificationController(Notifier notifier) {
        this.notifier = notifier;
    }

    @PostMapping("/notify")
    void notifyAuditors() {
        notifier.notifyAuditors();
    }
}
