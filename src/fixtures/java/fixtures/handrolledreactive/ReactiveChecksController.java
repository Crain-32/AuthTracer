package fixtures.handrolledreactive;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * RX-15: hand-rolled checks in reactive code. The caller comes from ReactiveSecurityContextHolder or the exchange,
 * read through method references and lambdas; the denial is an error signal or the response's status.
 */
@RestController
class ReactiveChecksController {

    @GetMapping("/reactive/admin")
    Mono<String> admin() {
        return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
                .flatMap(authentication -> authentication.getAuthorities().stream()
                        .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))
                        ? Mono.just("admin") : Mono.error(new AccessDeniedException("admins only")));
    }

    @GetMapping("/reactive/owners/{owner}")
    Flux<String> owned(@PathVariable String owner, ServerWebExchange exchange) {
        return exchange.getPrincipal().map(Principal::getName).flatMapMany(name -> name.equals(owner)
                ? Flux.just("a", "b")
                : Flux.error(() -> new ResponseStatusException(HttpStatus.FORBIDDEN, "not yours")));
    }

    @GetMapping("/reactive/ping")
    Mono<Void> ping(ServerWebExchange exchange) {
        if (exchange.getRequest().getHeaders().getFirst("X-Api-Key") == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        return Mono.empty();
    }

    /**
     * Reads the caller to greet them, denies nobody.
     */
    @GetMapping("/reactive/hello")
    Mono<String> hello() {
        return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
                .map(authentication -> "hello " + authentication.getName());
    }
}
