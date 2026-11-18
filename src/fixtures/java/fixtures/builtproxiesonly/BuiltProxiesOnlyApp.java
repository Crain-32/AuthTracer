package fixtures.builtproxiesonly;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0088 (amended): no method security, only a proxy factory the application builds with
 * {@code withDefaults()}. Its interceptors run the pre/post and {@code @AuthorizeReturnObject} annotations on the
 * objects it proxies; {@code @Secured}, which it has no interceptor for, never runs.
 */
@SpringBootApplication
class BuiltProxiesOnlyApp {
}

class Invoice {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public String getTotal() {
        return "100";
    }

    @Secured("ROLE_CLERK")
    public String getNumber() {
        return "42";
    }

    @AuthorizeReturnObject
    public Line getFirstLine() {
        return new Line();
    }
}

class Line {

    @PreAuthorize("hasRole('AUDITOR')")
    public String getAmount() {
        return "10";
    }
}

@RestController
class InvoiceController {

    private final AuthorizationProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();

    @GetMapping("/invoice/total")
    String total() {
        return ((Invoice) factory.proxy(new Invoice())).getTotal();
    }

    @GetMapping("/invoice/number")
    String number() {
        return ((Invoice) factory.proxy(new Invoice())).getNumber();
    }

    @GetMapping("/invoice/line")
    String line() {
        return ((Invoice) factory.proxy(new Invoice())).getFirstLine().getAmount();
    }
}
