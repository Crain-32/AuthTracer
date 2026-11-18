package fixtures.datarestimport;

import java.util.Optional;

import org.springframework.data.rest.core.annotation.RestResource;

/**
 * Invoices are listed, never read one by one: the item's lookup isn't exported.
 */
public interface InvoiceRepository extends BaseRepository<Invoice, Long> {

    @Override
    @RestResource(exported = false)
    Optional<Invoice> findById(Long id);
}
