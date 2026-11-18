package fixtures.fields;

import java.util.List;

import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.stereotype.Service;

@Service
class AccountService {

    /**
     * Elements of the returned list are authorization proxies.
     */
    @AuthorizeReturnObject
    public List<Account> all() {
        return List.of(new Account(1, "DE00 1234"));
    }

    /**
     * Returns the raw object: field checks on it never run.
     */
    public Account raw(long id) {
        return new Account(id, "DE00 5678");
    }
}
