package fixtures.customlibrary;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0120: an organisation's own authorization library, which Spring Security doesn't know. Its annotation is
 * enforced by an aspect, its guard by a call that throws; src/fixtures/resources/customlibrary/authtracer.yaml
 * describes both as rules.
 */
@SpringBootApplication
@EnableAspectJAutoProxy
public class CustomLibraryApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll()).httpBasic(basic -> { });
        return http.build();
    }
}

/**
 * The library's annotation: any of the permissions it names.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@interface RequiresPermission {

    String[] value();
}

/**
 * The library's guard: throws unless the caller holds PERM_ and the permission, or any of the permissions. One
 * overload calls the other, as libraries' do: the rule stands for both, and what they call.
 */
@Component
class Guard {

    void require(String permission) {
        require(new String[] {permission});
    }

    void require(String... permissions) {
        Authentication caller = SecurityContextHolder.getContext().getAuthentication();
        for (String permission : permissions) {
            if (caller != null && caller.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                    .anyMatch(("PERM_" + permission)::equals)) {
                return;
            }
        }
        throw new AccessDeniedException("missing any of " + Arrays.toString(permissions));
    }
}

/**
 * The library's aspect: a method annotated, or on a class annotated, needs any of the permissions it names; the
 * method's annotation over its class's.
 */
@Aspect
@Component
class PermissionAspect {

    @Autowired
    private Guard guard;

    @Before("@annotation(required)")
    void onMethod(RequiresPermission required) {
        check(required);
    }

    @Before("@within(required) && !@annotation(fixtures.customlibrary.RequiresPermission)")
    void onClass(RequiresPermission required) {
        check(required);
    }

    private void check(RequiresPermission required) {
        guard.require(required.value());
    }
}

@Service
class Orders {

    @RequiresPermission("orders.read")
    String list() {
        return "orders";
    }

    @RequiresPermission({"reports.read", "reports.admin"})
    String report() {
        return "report";
    }
}

@RestController
class OrdersController {

    private final Orders orders;
    private final Guard guard;

    OrdersController(Orders orders, Guard guard) {
        this.orders = orders;
        this.guard = guard;
    }

    @GetMapping("/orders")
    String list() {
        return orders.list();
    }

    @GetMapping("/reports")
    String report() {
        return orders.report();
    }

    @GetMapping("/orders/export")
    String export() {
        guard.require("orders.export");
        return "export";
    }

    @GetMapping("/orders/audit")
    String audit() {
        guard.require("audit.read", "audit.admin");
        return "audit";
    }

    @PostMapping("/orders/{action}")
    String act(@PathVariable String action) {
        guard.require("orders." + action);
        return action;
    }
}
