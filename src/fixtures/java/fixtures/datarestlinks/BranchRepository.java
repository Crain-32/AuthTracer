package fixtures.datarestlinks;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Its check guards its own items and a link to one, not an account's branch read through the account.
 */
public interface BranchRepository extends CrudRepository<Branch, Long> {

    @Override
    @PreAuthorize("hasRole('MANAGER')")
    Optional<Branch> findById(Long id);
}
