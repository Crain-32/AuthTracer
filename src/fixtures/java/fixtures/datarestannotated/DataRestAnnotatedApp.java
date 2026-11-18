package fixtures.datarestannotated;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

/**
 * Only the repositories annotated as exported are (spring.data.rest.detection-strategy=annotated), under
 * spring.data.rest.base-path.
 */
@SpringBootApplication
class DataRestAnnotatedApp {
}

class Product {

    private Long id;

    public Long getId() {
        return id;
    }
}

class Supplier {

    private Long id;

    public Long getId() {
        return id;
    }
}

class Warehouse {

    private Long id;

    public Long getId() {
        return id;
    }
}

@RepositoryRestResource(path = "catalog")
interface ProductRepository extends CrudRepository<Product, Long> {
}

@RepositoryRestResource(exported = false)
interface WarehouseRepository extends CrudRepository<Warehouse, Long> {
}
