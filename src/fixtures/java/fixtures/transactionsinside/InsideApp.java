package fixtures.transactionsinside;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Transactions wrap method security here (order 0 runs before 500), so a denial rolls the write back.
 */
@Configuration
@EnableMethodSecurity
@EnableTransactionManagement(order = 0)
class InsideApp {
}

@RestController
class ApprovalsController {

    private final ApprovalService approvals;

    ApprovalsController(ApprovalService approvals) {
        this.approvals = approvals;
    }

    @PostMapping("/approvals/{id}")
    String approve(@PathVariable long id) {
        return approvals.approve(id);
    }
}

@Service
class ApprovalService {

    @Transactional
    @PostAuthorize("returnObject == authentication.name")
    String approve(long id) {
        return "owner";
    }
}
