package fixtures.scheduled;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Decision 0046: scheduled tasks. The nightly job calls another service and a checked method, which fails without a
 * caller.
 */
@SpringBootApplication
@EnableScheduling
@EnableMethodSecurity
class ScheduledApp {
}

record Report(String name) {
}

@Service
class Payroll {

    @PreAuthorize("hasRole('PAYROLL')")
    public void close() {
    }
}

@Component
class Reports {

    private final RestClient client = RestClient.create("http://localhost:8091");

    private final Payroll payroll;

    Reports(Payroll payroll) {
        this.payroll = payroll;
    }

    @Scheduled(cron = "0 0 2 * * *")
    void nightly() {
        payroll.close();
        client.get().uri("/reports/daily").retrieve().body(Report.class);
    }

    @Scheduled(fixedRate = 60000)
    void heartbeat() {
    }
}
