package fixtures.plainrepositories;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Without Spring Boot or a SecurityEvaluationContextExtension bean, ?#{principal} can't be evaluated.
 */
@Configuration
@EnableMethodSecurity
class App {
}

record Message(Long id, String text) {
}

interface MessageRepository extends Repository<Message, Long> {

    @Query("select m from Message m where m.to.id = ?#{ principal?.id }")
    List<Message> findInbox();
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
}
