package fixtures.fields;

import java.math.BigDecimal;

import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class StatementController {

    private final Statements statements;

    StatementController(Statements statements) {
        this.statements = statements;
    }

    /**
     * Returned as is: serializing the proxy calls both checked getters.
     */
    @GetMapping("/statements/current")
    Statement current() {
        return statements.current();
    }

    @Service
    static class Statements {

        @AuthorizeReturnObject
        public Statement current() {
            return new Statement(BigDecimal.TEN, BigDecimal.ONE);
        }
    }
}
