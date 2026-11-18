package fixtures.streamaudit;

import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;

/**
 * A composed definition, enrich|store, whose functions each write to the checked audit log.
 */
@SpringBootApplication
@EnableMethodSecurity
class StreamAuditApp {

    @Bean
    Function<String, String> enrich(AuditLog audit) {
        return payment -> {
            audit.write("enriched " + payment);
            return payment.strip();
        };
    }

    @Bean
    Consumer<String> store(AuditLog audit) {
        return payment -> audit.write("stored " + payment);
    }
}

@Service
class AuditLog {

    @PreAuthorize("hasRole('AUDITOR')")
    public void write(String entry) {
    }
}
