package fixtures.fields;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.authorization.method.AuthorizeReturnObject;

/**
 * A Spring Data repository: a bean though the application doesn't implement it, and every result is proxied,
 * including what it inherits (findById).
 */
@AuthorizeReturnObject
interface AccountRepository extends CrudRepository<Account, Long> {
}
