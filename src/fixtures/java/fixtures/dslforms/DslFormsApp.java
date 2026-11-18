package fixtures.dslforms;

import java.util.function.Supplier;

import jakarta.servlet.DispatcherType;

import org.springframework.boot.security.autoconfigure.web.StaticResourceLocation;
import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * The DSL in the shapes real configurations take: a configurer disabled by method reference, the Builder bean handed
 * to the chain, the AuthorizationFilter post-processed, rules matched by HTTP method or dispatcher type alone, rules that need every listed authority, Boot's static resource locations narrowed,
 * and managers composed from Spring Security's static factories or written by hand.
 */
@Configuration
@EnableWebSecurity
class DslFormsConfig {

    @Bean
    PathPatternRequestMatcher.Builder paths() {
        return PathPatternRequestMatcher.withDefaults();
    }

    /**
     * HTTP-03: one regex rule and nothing after it, so a request it stops matching is denied.
     */
    @Bean
    @Order(1)
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        http.securityMatcher("/legacy/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(RegexRequestMatcher.regexMatcher("/legacy/[a-z]+")).fullyAuthenticated());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain app(HttpSecurity http, PathPatternRequestMatcher.Builder paths) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .withObjectPostProcessor(new ObjectPostProcessor<AuthorizationFilter>() {
                            @Override
                            public <O extends AuthorizationFilter> O postProcess(O filter) {
                                filter.setObserveOncePerRequest(true);
                                return filter;
                            }
                        })
                        // CORS preflight requests carry no credentials.
                        .requestMatchers(HttpMethod.OPTIONS).permitAll()
                        // Error dispatches: never a request's own dispatch.
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(PathRequest.toStaticResources().at(StaticResourceLocation.CSS,
                                StaticResourceLocation.JAVA_SCRIPT)).permitAll()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()
                                .excluding(StaticResourceLocation.WEB_JARS)).hasRole("DESIGNER")
                        .requestMatchers(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/items"))
                        .hasAllRoles("EDITOR", "PUBLISHER")
                        .requestMatchers(paths.matcher(HttpMethod.DELETE, "/items/{id}"))
                        .hasAllAuthorities("SCOPE_items.write", "SCOPE_items.delete")
                        .requestMatchers(RegexRequestMatcher.regexMatcher(HttpMethod.PUT)).fullyAuthenticated()
                        // Without a trailing .*, but what a request with a query string falls through to is the same.
                        .requestMatchers(RegexRequestMatcher.regexMatcher("/items/[0-9]+")).authenticated()
                        .requestMatchers("/session/**").rememberMe()
                        .requestMatchers("/audit/**").access(AuthorizationManagers.allOf(
                                AuthorityAuthorizationManager.hasRole("AUDITOR"),
                                AuthenticatedAuthorizationManager.fullyAuthenticated()))
                        .requestMatchers("/signup").access(AuthorizationManagers.not(
                                AuthenticatedAuthorizationManager.authenticated()))
                        .requestMatchers("/partners/**").access(AuthorityAuthorizationManager.hasAnyRole("PARTNER_",
                                new String[] { "GOLD", "SILVER" }))
                        .requestMatchers("/reports/**").access(OAuth2AuthorizationManagers.hasAllScopes("reports.read",
                                "reports.export"))
                        .requestMatchers("/office/**").access(new OfficeNetwork())
                        .anyRequest().authenticated());
        return http.build();
    }
}

/**
 * A hand-written manager: what it decides is in its own code.
 */
class OfficeNetwork implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(context.getRequest().getRemoteAddr().startsWith("10."));
    }
}

@RestController
class DslFormsController {

    @RequestMapping(path = "/items", method = RequestMethod.OPTIONS)
    void preflight() {
    }

    @GetMapping("/items")
    String items() {
        return "items";
    }

    @PostMapping("/items")
    String create() {
        return "created";
    }

    @GetMapping("/items/{id}")
    String item(@PathVariable long id) {
        return "item";
    }

    @GetMapping("/legacy/report")
    String legacyReport() {
        return "report";
    }

    @PutMapping("/items/{id}")
    String update(@PathVariable long id) {
        return "updated";
    }

    @DeleteMapping("/items/{id}")
    void delete(@PathVariable long id) {
    }

    @GetMapping("/css/site")
    String stylesheet() {
        return "body {}";
    }

    @GetMapping("/fonts/brand")
    String font() {
        return "font";
    }

    @GetMapping("/webjars/lib")
    String webjar() {
        return "lib";
    }

    @GetMapping("/session/refresh")
    String refresh() {
        return "refreshed";
    }

    @GetMapping("/audit/log")
    String audit() {
        return "log";
    }

    @GetMapping("/signup")
    String signup() {
        return "signup";
    }

    @GetMapping("/partners/deals")
    String deals() {
        return "deals";
    }

    @GetMapping("/reports/export")
    String export() {
        return "export";
    }

    @GetMapping("/office/printers")
    String printers() {
        return "printers";
    }
}
