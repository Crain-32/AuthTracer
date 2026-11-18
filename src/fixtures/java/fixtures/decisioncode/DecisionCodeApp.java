package fixtures.decisioncode;

import java.io.Serializable;
import java.util.Optional;
import java.util.function.Supplier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.repository.Repository;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Decision code AuthTracer reads: SpEL bean methods, custom managers and a PermissionEvaluator that delegate to root
 * functions or built-in managers, compare authorities, always grant or deny, throw a denial, read a repository, or
 * ask a remote policy engine.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class DecisionCodeConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/policy/**").access(new PolicyEngine())
                .requestMatchers("/delegated/**").access(new Delegating())
                .requestMatchers("/abstaining/**").access(new Abstaining())
                .requestMatchers("/either/**").access(new Either())
                .requestMatchers("/guarded/**").access(new Guarded())
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    static MethodSecurityExpressionHandler expressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(new Lenient());
        return handler;
    }
}

record Document(Long id, String owner) {
}

interface DocumentRepository extends Repository<Document, Long> {

    Optional<Document> findById(Long id);
}

@Component("rules")
class AccessRules {

    private final DocumentRepository documents;
    private final Teams teams;

    AccessRules(DocumentRepository documents, Teams teams) {
        this.documents = documents;
        this.teams = teams;
    }

    public boolean anyRole(MethodSecurityExpressionOperations operations, String... roles) {
        for (String role : roles) {
            if (operations.hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean member(Authentication authentication) {
        return teams.has(authentication.getName());
    }

    public boolean level(MethodSecurityExpressionOperations operations, int level) {
        return level > 3 || operations.hasRole("SENIOR");
    }

    public Boolean always() {
        return Boolean.TRUE;
    }

    public boolean isAdmin(MethodSecurityExpressionOperations operations) {
        return operations.hasRole("ADMIN");
    }

    public boolean operator(Authentication authentication) {
        return authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_OPS"))
                || authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_SRE"));
    }

    public boolean open() {
        return true;
    }

    public boolean closed() {
        return false;
    }

    public boolean auditor(MethodSecurityExpressionOperations operations) {
        if (!operations.hasRole("AUDITOR")) {
            throw new AuthorizationDeniedException("Auditors only");
        }
        return true;
    }

    public boolean fully(MethodSecurityExpressionOperations operations) {
        return operations.isFullyAuthenticated();
    }

    public boolean remembered(MethodSecurityExpressionOperations operations) {
        return operations.isRememberMe() || operations.isAuthenticated();
    }

    public boolean guest(MethodSecurityExpressionOperations operations) {
        return operations.isAnonymous();
    }

    public boolean billing() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        return AuthorityUtils.authorityListToSet(authentication.getAuthorities()).contains("ROLE_BILLING");
    }

    public Boolean boxed(MethodSecurityExpressionOperations operations) {
        return Boolean.valueOf(operations.hasRole("BOXED"));
    }

    public AuthorityAuthorizationManager<Object> managed() {
        return AuthorityAuthorizationManager.hasRole("MANAGER");
    }

    public boolean careful(MethodSecurityExpressionOperations operations) {
        try {
            return operations.hasRole("CAREFUL");
        }
        catch (RuntimeException e) {
            return true;
        }
    }

    public boolean named(Authentication authentication) {
        switch (authentication.getName()) {
            case "root":
                return true;
            default:
                return false;
        }
    }

    public boolean contradiction(MethodSecurityExpressionOperations operations) {
        return operations.hasRole("SOLO") && !operations.hasRole("SOLO");
    }

    public boolean unboxed(MethodSecurityExpressionOperations operations) {
        Boolean answer = operations.hasRole("UNBOXED");
        return answer;
    }

    public boolean strict(MethodSecurityExpressionOperations operations) {
        boolean strict = true;
        if (strict) {
            return operations.hasRole("STRICT");
        }
        return true;
    }

    public boolean legal(MethodSecurityExpressionOperations operations) {
        if (!operations.hasRole("LEGAL")) {
            throw new IllegalStateException("Not allowed");
        }
        return true;
    }

    public boolean owns(Long id, Authentication authentication) {
        return documents.findById(id).map(document -> document.owner().equals(authentication.getName()))
                .orElse(false);
    }
}

@Component
class Teams {

    boolean has(String name) {
        return name.startsWith("team-");
    }
}

/**
 * Asks a remote policy engine.
 */
class PolicyEngine implements AuthorizationManager<RequestAuthorizationContext> {

    private final RestClient opa = RestClient.create("http://opa:8181");

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        Boolean allowed = opa.post().uri("/v1/data/authz/allow").body(context.getRequest().getRequestURI())
                .retrieve().body(Boolean.class);
        return new AuthorizationDecision(Boolean.TRUE.equals(allowed));
    }
}

class Delegating implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return AuthorityAuthorizationManager.<RequestAuthorizationContext>hasRole("ADMIN")
                .authorize(authentication, context);
    }
}

/**
 * Asks a built-in manager and answers with what it decided.
 */
class Either implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        boolean granted = AuthorityAuthorizationManager.<RequestAuthorizationContext>hasAnyRole("FINANCE", "HR")
                .authorize(authentication, context).isGranted();
        return new AuthorizationDecision(granted);
    }
}

/**
 * Asks a built-in manager, and denies if it abstains.
 */
class Guarded implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        AuthorizationResult result = AuthorityAuthorizationManager.<RequestAuthorizationContext>hasRole("GUARD")
                .authorize(authentication, context);
        if (result == null) {
            return new AuthorizationDecision(false);
        }
        return result;
    }
}

/**
 * Abstains on every request, which lets it through.
 */
class Abstaining implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return null;
    }
}

/**
 * Grants every permission: permit-all in disguise.
 */
class Lenient implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        return true;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable id, String type, Object permission) {
        return true;
    }
}

@RestController
class DecisionCodeController {

    @GetMapping("/admin")
    @PreAuthorize("@rules.isAdmin(#root)")
    String admin() {
        return "admin";
    }

    @GetMapping("/operations")
    @PreAuthorize("@rules.operator(authentication)")
    String operations() {
        return "operations";
    }

    @GetMapping("/open")
    @PreAuthorize("@rules.open()")
    String open() {
        return "open";
    }

    @GetMapping("/closed")
    @PreAuthorize("@rules.closed()")
    String closed() {
        return "closed";
    }

    @GetMapping("/audit")
    @PreAuthorize("@rules.auditor(#root)")
    String audit() {
        return "audit";
    }

    @GetMapping("/fully")
    @PreAuthorize("@rules.fully(#root)")
    String fully() {
        return "fully";
    }

    @GetMapping("/remembered")
    @PreAuthorize("@rules.remembered(#root)")
    String remembered() {
        return "remembered";
    }

    @GetMapping("/guest")
    @PreAuthorize("@rules.guest(#root)")
    String guest() {
        return "guest";
    }

    @GetMapping("/billing")
    @PreAuthorize("@rules.billing()")
    String billing() {
        return "billing";
    }

    @GetMapping("/boxed")
    @PreAuthorize("@rules.boxed(#root)")
    String boxed() {
        return "boxed";
    }

    @GetMapping("/managed")
    @PreAuthorize("@rules.managed()")
    String managed() {
        return "managed";
    }

    @GetMapping("/careful")
    @PreAuthorize("@rules.careful(#root)")
    String careful() {
        return "careful";
    }

    @GetMapping("/named")
    @PreAuthorize("@rules.named(authentication)")
    String named() {
        return "named";
    }

    @GetMapping("/contradiction")
    @PreAuthorize("@rules.contradiction(#root)")
    String contradiction() {
        return "contradiction";
    }

    @GetMapping("/unboxed")
    @PreAuthorize("@rules.unboxed(#root)")
    String unboxed() {
        return "unboxed";
    }

    @GetMapping("/strict")
    @PreAuthorize("@rules.strict(#root)")
    String strict() {
        return "strict";
    }

    @GetMapping("/legal")
    @PreAuthorize("@rules.legal(#root)")
    String legal() {
        return "legal";
    }

    @GetMapping("/guarded/check")
    String guarded() {
        return "guarded";
    }

    @GetMapping("/any-role")
    @PreAuthorize("@rules.anyRole(#root, 'A', 'B')")
    String anyRole() {
        return "anyRole";
    }

    @GetMapping("/inherited")
    @PreAuthorize("@rules.inherited()")
    String inherited() {
        return "inherited";
    }

    @GetMapping("/member")
    @PreAuthorize("@rules.member(authentication)")
    String member() {
        return "member";
    }

    @GetMapping("/level/{level}")
    @PreAuthorize("@rules.level(#root, #level)")
    String level(@PathVariable int level) {
        return "level";
    }

    @GetMapping("/always")
    @PreAuthorize("@rules.always()")
    String always() {
        return "always";
    }

    @GetMapping("/either/check")
    String either() {
        return "either";
    }

    @GetMapping("/documents/{id}")
    @PreAuthorize("@rules.owns(#id, authentication)")
    String document(@PathVariable Long id) {
        return "document";
    }

    @GetMapping("/reports/{id}")
    @PreAuthorize("hasPermission(#id, 'Report', 'read')")
    String report(@PathVariable Long id) {
        return "report";
    }

    @GetMapping("/policy/check")
    String policy() {
        return "policy";
    }

    @GetMapping("/delegated/check")
    String delegated() {
        return "delegated";
    }

    @GetMapping("/abstaining/check")
    String abstaining() {
        return "abstaining";
    }
}
