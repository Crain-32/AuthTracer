package fixtures.datarestlinks;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.security.access.prepost.PreAuthorize;

public interface AccountRepository extends OwnedRepository<Account> {

    @Override
    @PreAuthorize("hasRole('TELLER')")
    Optional<Account> findById(Long id);
}

/**
 * A query method every repository of an owned type gets.
 */
@NoRepositoryBean
interface OwnedRepository<T> extends CrudRepository<T, Long> {

    List<T> findByOwner(String owner);
}
