package fixtures.proxies;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory.TargetVisitor;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Skipping value types only spares String and the like, which have no field checks: no finding.
 */
@Configuration
@EnableMethodSecurity
class ProxiesApp {

    @Bean
    static TargetVisitor skipValueTypes() {
        return TargetVisitor.defaultsSkipValueTypes();
    }
}

class Customer {

    private final String taxId;

    Customer(String taxId) {
        this.taxId = taxId;
    }

    @PreAuthorize("hasRole('ACCOUNTING')")
    public String getTaxId() {
        return taxId;
    }
}

class Invoice {

    @PreAuthorize("hasRole('BILLING')")
    public String getTotal() {
        return "100";
    }
}

@Component
class CustomerDirectory {

    List<Customer> all() {
        return List.of(new Customer("123"));
    }
}

/**
 * Class level: every result is proxied, the String one included.
 */
@Service
@AuthorizeReturnObject
class InvoiceService {

    public Invoice latest() {
        return new Invoice();
    }

    public String status() {
        return "open";
    }
}

@RestController
class ProxiesController {

    private final AuthorizationProxyFactory proxyFactory;
    private final CustomerDirectory directory;
    private final InvoiceService invoices;

    ProxiesController(AuthorizationProxyFactory proxyFactory, CustomerDirectory directory, InvoiceService invoices) {
        this.proxyFactory = proxyFactory;
        this.directory = directory;
        this.invoices = invoices;
    }

    @GetMapping("/customers")
    @SuppressWarnings("unchecked")
    String customers() {
        List<Customer> customers = (List<Customer>) proxyFactory.proxy(directory.all());
        return customers.getFirst().getTaxId();
    }

    @GetMapping("/invoices/latest")
    String latest() {
        return invoices.latest().getTotal();
    }
}
