package fixtures.xmlmatchers;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configured by WEB-INF/spring/security.xml: the beans its request-matcher-ref and authorization-manager-ref name.
 */
@RestController
class XmlMatchersEndpoints {

    @GetMapping("/partners/admin/keys")
    String keys() {
        return "keys";
    }

    @GetMapping("/partners/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/reports/sales/export")
    String export() {
        return "export";
    }

    @GetMapping("/reports/sales")
    String sales() {
        return "sales";
    }

    @GetMapping("/audit/pages/{page}")
    String page() {
        return "page";
    }

    @GetMapping("/audit/log")
    String log() {
        return "log";
    }

    @GetMapping("/internal/tools/reindex")
    String reindex() {
        return "reindex";
    }

    @GetMapping("/internal/any/status")
    String status() {
        return "status";
    }

    @GetMapping("/internal/flags/beta")
    String beta() {
        return "beta";
    }

    @GetMapping("/tenants/settings")
    String settings() {
        return "settings";
    }

    @GetMapping("/vendors/catalog")
    String catalog() {
        return "catalog";
    }

    @GetMapping("/legacy/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/legacy/secure/vault")
    String vault() {
        return "vault";
    }

    @GetMapping("/legacy/about")
    String about() {
        return "about";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}

@Component("partnerRequests")
class PartnerRequests implements RequestMatcher {

    @Override
    public boolean matches(HttpServletRequest request) {
        return request.getServletPath().startsWith("/partners");
    }
}

@Configuration
class XmlMatchersBeans {

    @Bean
    RequestMatcher internalRequests() {
        return request -> request.getHeader("X-Internal") != null;
    }

    @Bean
    RequestMatcher internalTools() {
        String prefix = "/internal/tools";
        return request -> request.getServletPath().startsWith(prefix);
    }

    @Bean
    RequestMatcher apiRequests() {
        return PathPatternRequestMatcher.withDefaults().matcher("/internal/api/**");
    }
}

/**
 * The tenants' manager: asks Spring's for the role.
 */
class TenantManager implements AuthorizationManager<HttpServletRequest> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            HttpServletRequest request) {
        return AuthorityAuthorizationManager.<HttpServletRequest>hasRole("TENANT").authorize(authentication, request);
    }
}
