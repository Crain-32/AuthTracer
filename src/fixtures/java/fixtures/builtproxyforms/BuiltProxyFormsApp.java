package fixtures.builtproxyforms;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.authorization.method.AuthorizeReturnObjectMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The other ways an application builds proxy factories: a factory bean of its own beside Spring Security's, lists
 * filled with {@code add(..)} or made by {@code Arrays.asList(..)}, and one of two factories.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class BuiltProxyFormsConfig {

    /**
     * A second factory bean: which one an injection point gets depends on names, so it may be this one.
     */
    @Bean
    static AuthorizationAdvisorProxyFactory reportsFactory() {
        return AuthorizationAdvisorProxyFactory.withDefaults();
    }
}

class Report {

    @Secured("ROLE_EDITOR")
    public String getTitle() {
        return "Q3";
    }

    @RolesAllowed("READER")
    public String getBody() {
        return "...";
    }

    @PostAuthorize("hasRole('REVIEWER')")
    public String getNotes() {
        return "draft";
    }

    @AuthorizeReturnObject
    public Report getPrevious() {
        return new Report();
    }
}

@RestController
class ReportController {

    private final AuthorizationProxyFactory injected;

    ReportController(AuthorizationProxyFactory injected) {
        this.injected = injected;
    }

    @GetMapping("/injected/title")
    String injectedTitle() {
        return injected.proxy(new Report()).getTitle();
    }

    @GetMapping("/added/body")
    String addedBody() {
        List<AuthorizationAdvisor> advisors = new ArrayList<>();
        advisors.add(AuthorizationManagerBeforeMethodInterceptor.jsr250());
        return new AuthorizationAdvisorProxyFactory(advisors).proxy(new Report()).getBody();
    }

    @GetMapping("/asList/previous/notes")
    String previousNotes() {
        AuthorizationProxyFactory factory = new AuthorizationAdvisorProxyFactory(Arrays.asList(
                AuthorizationManagerAfterMethodInterceptor.postAuthorize(), new AuthorizeReturnObjectMethodInterceptor()));
        return factory.proxy(new Report()).getPrevious().getNotes();
    }

    @GetMapping("/either/body")
    String eitherBody(@RequestParam boolean secured) {
        AuthorizationProxyFactory factory = secured
                ? new AuthorizationAdvisorProxyFactory(List.of(AuthorizationManagerBeforeMethodInterceptor.jsr250()))
                : AuthorizationAdvisorProxyFactory.withDefaults();
        return factory.proxy(new Report()).getBody();
    }
}
