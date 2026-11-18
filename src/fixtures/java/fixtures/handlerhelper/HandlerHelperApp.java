package fixtures.handlerhelper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The expression handler bean is made and set up in a helper: hasRole('LEAD') asks for TEAM_LEAD.
 */
@Configuration
@EnableMethodSecurity
class HandlerHelperConfig {

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        return teamHandler();
    }

    private static DefaultMethodSecurityExpressionHandler teamHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setDefaultRolePrefix("TEAM_");
        return handler;
    }
}

@RestController
class ReportsController {

    @GetMapping("/reports")
    @PreAuthorize("hasRole('LEAD')")
    String reports() {
        return "reports";
    }
}
