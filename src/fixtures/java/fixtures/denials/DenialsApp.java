package fixtures.denials;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.authorization.method.HandleAuthorizationDenied;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Denial handlers on the field checks of an object an {@code @AuthorizeReturnObject} method returns: Spring's
 * throwing one, one that masks the denied result, one that answers a constant, and meta-annotations whose handler
 * reads the annotation's parameters (from Spring Security's reference, "Deciding What to Return Based on Available
 * Parameters").
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true)
class DenialsConfig {
}

/**
 * Keeps the last four characters of the denied result; answers a constant before the method ran. A bean, as Spring
 * Security looks a handler up among them.
 */
@Component
class LastFour implements MethodAuthorizationDeniedHandler {

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return "****";
    }

    @Override
    public Object handleDeniedInvocationResult(MethodInvocationResult invocation, AuthorizationResult result) {
        String value = (String) invocation.getResult();
        return "****" + value.substring(value.length() - 4);
    }
}

/**
 * Answers a constant whenever it denies: the interface's handleDeniedInvocationResult delegates here.
 */
@Component
class Hidden implements MethodAuthorizationDeniedHandler {

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return "hidden";
    }
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@HandleAuthorizationDenied(handlerClass = MaskAnnotationHandler.class)
@interface Mask {

    String value();
}

/**
 * Answers the {@code @Mask} value of the method it denied.
 */
@Component
class MaskAnnotationHandler implements MethodAuthorizationDeniedHandler {

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return AnnotationUtils.getAnnotation(invocation.getMethod(), Mask.class).value();
    }

    @Override
    public Object handleDeniedInvocationResult(MethodInvocationResult invocation, AuthorizationResult result) {
        Mask mask = AnnotationUtils.getAnnotation(invocation.getMethodInvocation().getMethod(), Mask.class);
        return mask.value();
    }
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@HandleAuthorizationDenied(handlerClass = ObscuringHandler.class)
@interface Obscured {

    int visible();
}

@Component
class Obscurer {

    String obscure(Object value, int visible) {
        String text = String.valueOf(value);
        return "*".repeat(text.length() - visible) + text.substring(text.length() - visible);
    }
}

/**
 * Hands the denied result to a bean, with the {@code @Obscured} parameter.
 */
@Component
class ObscuringHandler implements MethodAuthorizationDeniedHandler {

    private final Obscurer obscurer;

    ObscuringHandler(Obscurer obscurer) {
        this.obscurer = obscurer;
    }

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return null;
    }

    @Override
    public Object handleDeniedInvocationResult(MethodInvocationResult invocation, AuthorizationResult result) {
        Obscured obscured = AnnotationUtils.getAnnotation(invocation.getMethodInvocation().getMethod(),
                Obscured.class);
        return obscurer.obscure(invocation.getResult(), obscured.visible());
    }
}

class Account {

    private final String owner;
    private final String iban;
    private final String pin;
    private final String phone;
    private final String note;
    private final String email;

    Account(String owner, String iban, String pin, String phone, String note, String email) {
        this.owner = owner;
        this.iban = iban;
        this.pin = pin;
        this.phone = phone;
        this.note = note;
        this.email = email;
    }

    /**
     * Spring's handler named explicitly: it throws, as the default does.
     */
    @PostAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = ThrowingMethodAuthorizationDeniedHandler.class)
    public String getOwner() {
        return owner;
    }

    @PostAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = LastFour.class)
    public String getIban() {
        return iban;
    }

    /**
     * Denied before it runs: the handler has no result to mask.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = LastFour.class)
    public String getPin() {
        return pin;
    }

    @PostAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = Hidden.class)
    public String getPhone() {
        return phone;
    }

    @PostAuthorize("hasRole('AUDITOR')")
    @Mask("redacted")
    public String getNote() {
        return note;
    }

    @PostAuthorize("hasRole('AUDITOR')")
    @Obscured(visible = 3)
    public String getEmail() {
        return email;
    }
}

record Summary(String iban) {
}

/**
 * A handler no bean is: 7.1.1's PostAuthorizeExpressionAttributeRegistry looks it up among the beans and, finding
 * none, fails every call of the method it is named on.
 */
class Unregistered implements MethodAuthorizationDeniedHandler {

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return "unregistered";
    }
}

class Card {

    @PostAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = Unregistered.class)
    public String getNumber() {
        return "4111";
    }

    public String getBrand() {
        return "visa";
    }
}

class Branch {

    /**
     * Only @PreAuthorize and @PostAuthorize read @HandleAuthorizationDenied: @Secured's manager throws.
     */
    @Secured("ROLE_TELLER")
    @HandleAuthorizationDenied(handlerClass = Hidden.class)
    public String getManager() {
        return "manager";
    }

    public String getName() {
        return "main";
    }
}

@Service
class Accounts {

    @AuthorizeReturnObject
    public Account find(long id) {
        return raw(id);
    }

    @AuthorizeReturnObject
    public Card card(long id) {
        return new Card();
    }

    @AuthorizeReturnObject
    public Branch branch(long id) {
        return new Branch();
    }

    public Account raw(long id) {
        return new Account("owner" + id, "iban", "pin", "phone", "note", "email");
    }
}

@RestController
class DenialsController {

    private final Accounts accounts;

    DenialsController(Accounts accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/accounts/{id}")
    Account account(@PathVariable long id) {
        return accounts.find(id);
    }

    /**
     * Not a proxy: no check runs, so no handler answers.
     */
    @GetMapping("/accounts/{id}/raw")
    Account raw(@PathVariable long id) {
        return accounts.raw(id);
    }

    /**
     * The code reads the masked getter on the proxy.
     */
    @GetMapping("/accounts/{id}/summary")
    Summary summary(@PathVariable long id) {
        return new Summary(accounts.find(id).getIban());
    }

    @GetMapping("/cards/{id}")
    Card card(@PathVariable long id) {
        return accounts.card(id);
    }

    @GetMapping("/branches/{id}")
    Branch branch(@PathVariable long id) {
        return accounts.branch(id);
    }
}
