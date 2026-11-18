package fixtures.handrolled;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks written by hand instead of with Spring Security's mechanisms.
 */
@RestController
class LegacyController {

    @GetMapping("/legacy/{id}")
    String secret(@PathVariable long id, Authentication authentication) {
        if (authentication.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            throw new AccessDeniedException("admins only");
        }
        return "secret " + id;
    }

    @GetMapping("/legacy/manual")
    ResponseEntity<String> manual(HttpServletRequest request) {
        if (!request.isUserInRole("ADMIN")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok("manual");
    }

    @GetMapping("/legacy/owned/{owner}")
    String owned(@PathVariable String owner, @AuthenticationPrincipal UserDetails me) {
        if (!owner.equals(me.getUsername())) {
            throw new AccessDeniedException("not yours");
        }
        return "owned";
    }

    /**
     * Reads the caller but never denies: not a check.
     */
    @GetMapping("/legacy/whoami")
    String whoami(Authentication authentication) {
        return authentication.getName();
    }

    /**
     * Reflection hides what runs next.
     */
    @GetMapping("/legacy/dynamic")
    Object dynamic() throws Exception {
        return Class.forName("fixtures.handrolled.Plugin").getMethod("run").invoke(null);
    }
}
