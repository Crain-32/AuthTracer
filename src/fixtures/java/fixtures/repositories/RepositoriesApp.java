package fixtures.repositories;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks on a Spring Data repository's own methods: method security, and a query that only returns the caller's
 * rows.
 */
@Configuration
@EnableMethodSecurity
class RepositoriesConfig {

    @Bean
    SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
}

record Message(Long id, String text) {
}

interface MessageRepository extends Repository<Message, Long> {

    @Query("select m from Message m where m.to.id = ?#{ principal?.id }")
    List<Message> findInbox();

    @PreAuthorize("hasRole('ADMIN')")
    void deleteById(Long id);
}

@RestController
class MessageController {

    private final MessageRepository messages;

    MessageController(MessageRepository messages) {
        this.messages = messages;
    }

    @GetMapping("/inbox")
    List<Message> inbox() {
        return messages.findInbox();
    }

    @DeleteMapping("/messages/{id}")
    void delete(@PathVariable("id") Long id) {
        messages.deleteById(id);
    }
}
