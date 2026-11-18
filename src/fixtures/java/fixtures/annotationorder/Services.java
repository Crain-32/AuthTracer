package fixtures.annotationorder;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * Where Spring Security 7.1.1 finds a method's annotation: the method, then the methods it overrides, then the class
 * and the classes and interfaces above it. JSR-250's three annotations are one group: the closest wins.
 */
abstract class BaseService {

    @PreAuthorize("hasRole('ADMIN')")
    public abstract void purge();
}

@Service
class ReportService extends BaseService {

    @Override
    public void purge() {
    }
}

class User {
}

interface CrudApi<T> {

    @PreAuthorize("hasRole('ADMIN')")
    void delete(T item);
}

@Service
class UserService implements CrudApi<User> {

    @Override
    public void delete(User user) {
    }
}

interface Audits {

    @PreAuthorize("hasRole('AUDITOR')")
    void export();
}

@Service
@PreAuthorize("isAuthenticated()")
class AuditService implements Audits {

    @Override
    public void export() {
    }
}

@PreAuthorize("hasRole('STAFF')")
abstract class StaffOnly {
}

@Service
class Rota extends StaffOnly {

    public String view() {
        return "rota";
    }
}

@Service
@RolesAllowed("ADMIN")
class Reports {

    @PermitAll
    public String published() {
        return "published";
    }

    public String drafts() {
        return "drafts";
    }
}

@Service
@DenyAll
class Vault {

    @RolesAllowed("KEEPER")
    public String open() {
        return "open";
    }
}
