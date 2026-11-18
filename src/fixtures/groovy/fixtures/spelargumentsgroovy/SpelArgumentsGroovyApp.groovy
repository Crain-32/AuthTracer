package fixtures.spelargumentsgroovy

import org.springframework.context.annotation.Configuration
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.core.parameters.P
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

/**
 * EXPR-02 in Groovy, compiled without parameter names: Spring finds {@code #owner} only through {@code @P}.
 */
@Configuration
@EnableMethodSecurity
class SpelArgumentsGroovyConfig {
}

@Service
class Accounts {

    @PreAuthorize('#owner == authentication.name')
    String owned(String owner) {
        owner
    }

    @PreAuthorize('#owner == authentication.name')
    String named(@P('owner') String owner) {
        owner
    }
}

@RestController
class AccountsController {

    private final Accounts accounts

    AccountsController(Accounts accounts) {
        this.accounts = accounts
    }

    @GetMapping('/accounts/{owner}')
    String owned(@PathVariable('owner') String owner) {
        accounts.owned(owner)
    }

    @GetMapping('/named/{owner}')
    String named(@PathVariable('owner') String owner) {
        accounts.named(owner)
    }
}
