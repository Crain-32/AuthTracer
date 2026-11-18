package fixtures.streamcompose;

import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;

/**
 * Decision 0047: a composed definition, validate|store, whose second function reaches a check; its destination is a
 * placeholder.
 */
@SpringBootApplication
@EnableMethodSecurity
class StreamComposeApp {

    @Bean
    Function<String, String> validate() {
        return value -> value.trim();
    }

    @Bean
    Consumer<String> store(Repository repository) {
        return value -> repository.save(value);
    }
}

@Service
class Repository {

    @PreAuthorize("hasRole('WRITER')")
    public void save(String value) {
    }
}
