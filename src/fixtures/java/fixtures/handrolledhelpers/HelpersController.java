package fixtures.handrolledhelpers;

import java.security.Principal;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Hand-rolled checks split across a helper (the condition in one method, the denial in another), and the other ways
 * code denies: a ResponseEntity made with a denial status, an exception the application annotates with
 * {@code @ResponseStatus(FORBIDDEN)} or that extends AccessDeniedException under a neutral name, and the principal
 * Spring hands in as a type of the application's.
 */
@RestController
class HelpersController {

    private final Archive archive;

    HelpersController(Archive archive) {
        this.archive = archive;
    }

    @GetMapping("/documents/{owner}")
    String document(@PathVariable String owner, Authentication authentication) {
        if (!owner.equals(authentication.getName())) {
            forbidden();
        }
        return "document";
    }

    @GetMapping("/admin/report")
    String report(Authentication authentication) {
        if (!isAdmin(authentication)) {
            throw new AccessDeniedException("admins only");
        }
        return "report";
    }

    @GetMapping("/guarded")
    String guarded(Principal principal) {
        Guards.require(principal.getName().startsWith("ops-"));
        return "guarded";
    }

    @GetMapping("/entities/{owner}")
    ResponseEntity<String> entity(@PathVariable String owner, Principal principal) {
        if (!owner.equals(principal.getName())) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        return ResponseEntity.ok("entity");
    }

    @GetMapping("/accounts/{id}")
    ResponseEntity<String> account(@PathVariable long id, @AuthenticationPrincipal Account account) {
        if (account.id() != id) {
            return ResponseEntity.status(HttpStatus.valueOf(403)).build();
        }
        return ResponseEntity.ok("account");
    }

    @GetMapping("/vaults/{owner}")
    String vault(@PathVariable String owner, Principal principal) {
        if (!owner.equals(principal.getName())) {
            throw new NotPermitted();
        }
        return "vault";
    }

    @GetMapping("/locks/{owner}")
    String lock(@PathVariable String owner, Principal principal) {
        if (!owner.equals(principal.getName())) {
            throw new LockedOut();
        }
        return "lock";
    }

    /**
     * Hides the record: not a check, though the helper reads the caller.
     */
    @GetMapping("/hidden/{owner}")
    String hidden(@PathVariable String owner, Authentication authentication) {
        if (!isAdmin(authentication)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "hidden";
    }

    /**
     * The archive denies by itself: that check is the archive's, not this handler's.
     */
    @GetMapping("/archive/{owner}")
    String archived(@PathVariable String owner, Principal principal) {
        return archive.open(owner, principal.getName().length());
    }

    /**
     * The helper is the check: reported as its own, not again as the handler's.
     */
    @GetMapping("/admin/settings")
    String settings(Authentication authentication) {
        requireAdmin(authentication);
        return "settings";
    }

    @GetMapping("/notes/{owner}")
    String notes(@PathVariable String owner, Authentication authentication) {
        String reader = authentication.getName();
        requireOwner(owner, authentication);
        return "notes for " + reader;
    }

    private static void requireOwner(String owner, Authentication authentication) {
        if (!owner.equals(authentication.getName())) {
            throw new AccessDeniedException("not yours");
        }
    }

    private void requireAdmin(Authentication authentication) {
        if (!isAdmin(authentication)) {
            throw new AccessDeniedException("admins only");
        }
    }

    private static boolean isAdmin(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
    }

    private static void forbidden() {
        throw new AccessDeniedException("not yours");
    }
}

class Guards {

    static void require(boolean allowed) {
        if (!allowed) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}

@Service
class Archive {

    String open(String owner, int length) {
        if (length > 64) {
            throw new AccessDeniedException("too long");
        }
        return owner;
    }
}

record Account(long id) {
}

@ResponseStatus(HttpStatus.FORBIDDEN)
class NotPermitted extends RuntimeException {
}

class LockedOut extends AccessDeniedException {

    LockedOut() {
        super("locked out");
    }
}
