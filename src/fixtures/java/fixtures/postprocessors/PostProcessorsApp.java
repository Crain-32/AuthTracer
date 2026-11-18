package fixtures.postprocessors;

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-19: post-processors on the authorization configurer. The application's chain only stops the
 * AuthorizationFilter from checking error and async dispatches; the admin chain wraps the request manager in an
 * auditing one; the partner chain hands the builder and the filter a post-processor from a field; the tenant chain replaces
 * the filter. Every chain's manager also goes through an ObjectPostProcessor bean.
 */
@SpringBootApplication
class PostProcessorsApp {

    private final ObjectPostProcessor<Object> shared = ObjectPostProcessor.identity();

    @Bean
    ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> timing() {
        return new ObjectPostProcessor<>() {
            @Override
            public <O extends AuthorizationManager<HttpServletRequest>> O postProcess(O manager) {
                return manager;
            }
        };
    }

    @Bean
    @Order(1)
    SecurityFilterChain admin(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**")
                .authorizeHttpRequests(authorize -> authorize
                        .withObjectPostProcessor(new AuditingPostProcessor())
                        .anyRequest().hasRole("ADMIN"));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        http.securityMatcher("/partners/**")
                .objectPostProcessor(shared)
                .authorizeHttpRequests(authorize -> authorize
                        .withObjectPostProcessor(shared)
                        .anyRequest().hasRole("PARTNER"));
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain tenants(HttpSecurity http) throws Exception {
        http.securityMatcher("/tenants/**")
                .authorizeHttpRequests(authorize -> authorize
                        .withObjectPostProcessor(new ObjectPostProcessor<AuthorizationFilter>() {
                            @Override
                            @SuppressWarnings("unchecked")
                            public <O extends AuthorizationFilter> O postProcess(O filter) {
                                return (O) new TenantAuthorizationFilter(filter.getAuthorizationManager());
                            }
                        })
                        .anyRequest().hasRole("TENANT"));
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .withObjectPostProcessor(new ObjectPostProcessor<AuthorizationFilter>() {
                    @Override
                    public <O extends AuthorizationFilter> O postProcess(O filter) {
                        filter.setFilterErrorDispatch(false);
                        filter.setFilterAsyncDispatch(false);
                        return filter;
                    }
                })
                .anyRequest().authenticated());
        return http.build();
    }
}

/**
 * The filter that also checks the tenant a request names.
 */
class TenantAuthorizationFilter extends AuthorizationFilter {

    TenantAuthorizationFilter(AuthorizationManager<HttpServletRequest> manager) {
        super(manager);
    }
}

/**
 * Wraps the request manager to record each decision.
 */
class AuditingPostProcessor implements ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> {

    @Override
    @SuppressWarnings("unchecked")
    public <O extends AuthorizationManager<HttpServletRequest>> O postProcess(O manager) {
        AuthorizationManager<HttpServletRequest> audited = new AuthorizationManager<>() {
            @Override
            public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
                    HttpServletRequest request) {
                return manager.authorize(authentication, request);
            }
        };
        return (O) audited;
    }
}

@RestController
class PostProcessorsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/partners/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/tenants/acme")
    String tenant() {
        return "acme";
    }

    @GetMapping("/profile")
    String profile() {
        return "profile";
    }
}

@Controller
class OopsController implements ErrorController {

    @GetMapping("/error")
    @ResponseBody
    String error() {
        return "Something went wrong";
    }
}
