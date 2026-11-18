package fixtures.scheduledhandoff;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.service.annotation.PostExchange;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * A month-end job that closes two ledgers through the same checked method, sends the statements through an HTTP
 * service client, then hands the archive to an {@code @Async} service whose method is checked too.
 */
@SpringBootApplication
@EnableScheduling
@EnableAsync
@EnableMethodSecurity
@ImportHttpServices(group = "statements", types = StatementsClient.class)
class ScheduledHandoffApp {
}

interface StatementsClient {

    @PostExchange("/statements/{month}")
    void send(@PathVariable String month);
}

@Service
class Ledgers {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public void close(String ledger) {
    }
}

@Service
class Archive {

    @Async
    @PreAuthorize("hasRole('ARCHIVIST')")
    public void store(String ledger) {
    }
}

@Component
class MonthEnd {

    private final Ledgers ledgers;

    private final Archive archive;

    private final StatementsClient statements;

    MonthEnd(Ledgers ledgers, Archive archive, StatementsClient statements) {
        this.ledgers = ledgers;
        this.archive = archive;
        this.statements = statements;
    }

    @Scheduled(cron = "0 0 1 1 * *")
    void close() {
        ledgers.close("payables");
        ledgers.close("receivables");
        statements.send("month");
        archive.store("month");
    }
}
