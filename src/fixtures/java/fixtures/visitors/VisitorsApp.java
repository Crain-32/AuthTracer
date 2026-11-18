package fixtures.visitors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory.TargetVisitor;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * This visitor hands Badge back unproxied, so its field check never runs.
 */
@Configuration
@EnableMethodSecurity
class VisitorsApp {

    @Bean
    static TargetVisitor skipBadges() {
        return (factory, target) -> target instanceof Badge ? target : null;
    }
}

class Badge {

    @PreAuthorize("hasRole('SECURITY')")
    public String getCode() {
        return "1234";
    }
}

@Service
class BadgeService {

    @AuthorizeReturnObject
    public Badge issue() {
        return new Badge();
    }
}

@RestController
class BadgeController {

    private final BadgeService badges;

    BadgeController(BadgeService badges) {
        this.badges = badges;
    }

    @GetMapping("/badge")
    String badge() {
        return badges.issue().getCode();
    }
}
