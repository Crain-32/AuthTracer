package fixtures.streamotherbinder;

import java.util.function.Consumer;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Decision 0047: a function bound by a binder AuthTracer doesn't know (Google Cloud Pub/Sub's) is no Kafka or
 * RabbitMQ entry point, though the Kafka binder is on the classpath too.
 */
@SpringBootApplication
class StreamOtherBinderApp {

    @Bean
    Consumer<String> audit() {
        return entry -> {
        };
    }
}
