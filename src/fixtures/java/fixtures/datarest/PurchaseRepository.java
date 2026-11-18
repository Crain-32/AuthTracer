package fixtures.datarest;

import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Data REST calls the CRUD methods Spring Data picks: delete(Purchase) before the inherited deleteById, and
 * findAll(Pageable) before findAll(); an item's PUT, PATCH and DELETE load it through findById first.
 */
public interface PurchaseRepository extends PagingAndSortingRepository<Purchase, Long>,
        CrudRepository<Purchase, Long> {

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    void delete(Purchase purchase);

    @Override
    @PreAuthorize("hasRole('CLERK')")
    Optional<Purchase> findById(Long id);

    @Override
    @PreAuthorize("hasRole('PAGER')")
    Page<Purchase> findAll(Pageable pageable);

    @Override
    Iterable<Purchase> findAll();
}

class Purchase {

    private Long id;

    public Long getId() {
        return id;
    }
}
