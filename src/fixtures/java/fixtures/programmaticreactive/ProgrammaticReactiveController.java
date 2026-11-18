package fixtures.programmaticreactive;

import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * AUTHZ-11 on WebFlux: {@code verify(..)} on a ReactiveAuthorizationManager checks when its Mono is part of what the
 * handler returns, and checks nothing when the Mono is dropped.
 */
@RestController
class ProgrammaticReactiveController {

    private final ReactiveAuthorizationManager<String> operators = AuthorityReactiveAuthorizationManager
            .hasRole("OPERATOR");

    @GetMapping("/reactive/restart")
    Mono<String> restart() {
        return operators.verify(ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication),
                "restart").thenReturn("restarted");
    }

    @GetMapping("/reactive/flush")
    Mono<String> flush() {
        operators.verify(ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication), "flush");
        return Mono.just("flushed");
    }
}
