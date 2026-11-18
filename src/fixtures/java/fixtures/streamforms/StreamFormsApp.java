package fixtures.streamforms;

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Decision 0047 on RabbitMQ, the default binder, with one binding on Kafka and one on a binder AuthTracer doesn't
 * know: a function bean named by its {@code @Bean}, a supplier component, and a definition that names a function
 * the application doesn't have.
 */
@SpringBootApplication
class StreamFormsApp {

    @Bean(name = "audit")
    Consumer<String> auditor() {
        return entry -> {
        };
    }

    @Bean
    Function<String, String> enrich() {
        return raw -> raw.trim();
    }

    @Bean
    Consumer<String> inventory() {
        return count -> {
        };
    }
}

/**
 * Polled by the binder, named by its stereotype after an annotation that isn't one.
 */
@Profile("!test")
@Component("ticker")
class Ticker implements Supplier<String> {

    @Override
    public String get() {
        return "tick";
    }
}
