package fixtures.datarestlinks;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;

public interface TransactionRepository extends CrudRepository<Transaction, Long> {

    @Override
    @PreAuthorize("hasRole('AUDITOR')")
    Iterable<Transaction> findAll();

    @Override
    @PreAuthorize("hasRole('AUDITOR')")
    Optional<Transaction> findById(Long id);
}
