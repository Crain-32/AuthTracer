package fixtures.handrolledcorners;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Hand-rolled checks (AUTHZ-15, RX-15): one whose read and denial are each in a helper of its own, and code that
 * looks like a check but isn't one. It answers 404, errors with something other than a denial, reads a header that
 * carries no credential, or takes the principal and never uses it.
 */
@RestController
class CornersController {

    @GetMapping("/ledger/{owner}")
    String ledger(@PathVariable String owner) {
        if (!owner.equals(caller())) {
            refuse();
        }
        return "ledger";
    }

    private static String caller() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    private static void refuse() {
        throw new org.springframework.security.access.AccessDeniedException("not yours");
    }

    @GetMapping("/missing")
    void missing(Authentication authentication, HttpServletResponse response) throws IOException {
        if (authentication.getName().isEmpty()) {
            response.sendError(404);
        }
    }

    @GetMapping("/gone")
    ResponseEntity<String> gone(Authentication authentication, int code) {
        if (authentication.getName().isEmpty()) {
            return ResponseEntity.status(HttpStatus.valueOf(404)).build();
        }
        return ResponseEntity.status(HttpStatus.valueOf(code)).build();
    }

    @GetMapping("/hidden-thing")
    String hiddenThing(Authentication authentication) {
        if (authentication.getName().isEmpty()) {
            throw new ThingNotFound();
        }
        return "thing";
    }

    @GetMapping("/broken")
    Mono<String> broken() {
        return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
                .flatMap(authentication -> authentication.getName().isEmpty()
                        ? Mono.error(() -> new IllegalStateException("no name")) : Mono.just("ok"));
    }

    @GetMapping("/stream")
    Flux<String> stream() {
        return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
                .flatMapMany(authentication -> authentication.getName().isEmpty()
                        ? Flux.error(new IllegalStateException("no name"), true) : Flux.just("ok"));
    }

    @GetMapping("/traced")
    String traced(HttpServletRequest request, HttpServletResponse response, String header) throws IOException {
        if (request.getHeader("X-Trace") == null || request.getHeader(header) == null) {
            response.sendError(403);
        }
        return "traced";
    }

    @GetMapping("/unused")
    String unused(@AuthenticationPrincipal Object principal, HttpServletResponse response) throws IOException {
        response.sendError(403);
        return "unused";
    }
}

@ResponseStatus(HttpStatus.NOT_FOUND)
class ThingNotFound extends RuntimeException {
}
