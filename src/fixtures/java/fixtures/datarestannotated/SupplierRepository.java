package fixtures.datarestannotated;

import org.springframework.data.repository.CrudRepository;

/**
 * Public, but not annotated.
 */
public interface SupplierRepository extends CrudRepository<Supplier, Long> {
}
