package fixtures.async;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Decision 0048: @Async methods run without the caller's SecurityContext, so the checks they reach deny and the
 * token they would relay isn't there.
 */
@SpringBootApplication
@EnableAsync
@EnableMethodSecurity
class AsyncApp {
}

@Service
class Audit {

    @PreAuthorize("hasRole('AUDITOR')")
    public void record(String user) {
    }
}

@Service
class Notifier {

    private final Audit audit;

    private final WebClient client = WebClient.builder().baseUrl("http://localhost:8092")
            .filter(new ServletBearerExchangeFilterFunction()).build();

    Notifier(Audit audit) {
        this.audit = audit;
    }

    @Async
    public void notifyUser(String user) {
        audit.record(user);
        client.post().uri("/notifications/{user}", user).retrieve().toBodilessEntity().block();
    }

    @Async
    @PreAuthorize("hasRole('ADMIN')")
    public void purge() {
    }

    @Async
    @PreAuthorize("hasRole('ARCHIVIST')")
    public void archive() {
    }
}

@RestController
class NotificationController {

    private final Notifier notifier;

    private final Audit audit;

    NotificationController(Notifier notifier, Audit audit) {
        this.notifier = notifier;
        this.audit = audit;
    }

    @PostMapping("/notify/{user}")
    void notifyUser(@PathVariable String user) {
        audit.record(user);
        notifier.notifyUser(user);
    }

    @DeleteMapping("/notifications")
    void purge() {
        notifier.purge();
    }

    @PostMapping("/notifications/cleanup")
    void cleanup(@org.springframework.web.bind.annotation.RequestParam boolean archive) {
        if (archive) {
            notifier.archive();
        }
        else {
            notifier.purge();
        }
    }
}
