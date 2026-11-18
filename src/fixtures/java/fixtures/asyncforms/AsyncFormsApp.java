package fixtures.asyncforms;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0048: {@code @Async} on a class makes each of its methods run on another thread.
 */
@SpringBootApplication
@EnableAsync
@EnableMethodSecurity
class AsyncFormsApp {
}

@Service
class Audit {

    @PreAuthorize("hasRole('AUDITOR')")
    public void record(String entry) {
    }
}

@Service
@Async
class Mailer {

    private final Audit audit;

    Mailer(Audit audit) {
        this.audit = audit;
    }

    public void send(String to) {
        audit.record(to);
    }
}

@RestController
class MailController {

    private final Mailer mailer;

    MailController(Mailer mailer) {
        this.mailer = mailer;
    }

    @PostMapping("/mail")
    void mail(@RequestParam String to) {
        mailer.send(to);
    }
}
