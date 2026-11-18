package fixtures.handrolledforms;

import java.io.IOException;
import java.security.Principal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The other ways code denies by hand: a status exception, the servlet response's status, a status code, and an
 * exception of the application's own.
 */
@RestController
class AccountsController {

    @GetMapping("/accounts/{owner}")
    String account(@PathVariable String owner, Principal principal) {
        if (!owner.equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "not your account");
        }
        return "account";
    }

    /**
     * Hides the account rather than denying: not a check.
     */
    @GetMapping("/accounts/{owner}/statement")
    String statement(@PathVariable String owner, Principal principal) {
        if (!owner.equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "statement";
    }

    @GetMapping("/reports")
    void reports(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getRemoteUser() == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        if (!request.isUserInRole("ANALYST")) {
            response.sendError(HttpStatus.FORBIDDEN.value());
            return;
        }
        response.getWriter().write("reports");
    }

    @GetMapping("/exports")
    void exports(Authentication authentication, HttpServletResponse response) {
        if (authentication.getAuthorities().isEmpty()) {
            response.setStatus(403);
        }
    }

    @GetMapping("/tokens")
    ResponseEntity<String> tokens(@AuthenticationPrincipal Jwt jwt) {
        if (!"ops".equals(jwt.getClaimAsString("team"))) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok("tokens");
    }

    @GetMapping("/teams/{team}")
    String team(@PathVariable String team, @AuthenticationPrincipal Jwt jwt) {
        if (!team.equals(jwt.getClaimAsString("team"))) {
            throw new TeamAccessDeniedException(team);
        }
        return "team";
    }
}

class TeamAccessDeniedException extends RuntimeException {

    TeamAccessDeniedException(String team) {
        super("not a member of " + team);
    }
}
