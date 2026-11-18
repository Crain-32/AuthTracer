package fixtures.datarestall;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

/**
 * spring.data.rest.detection-strategy=all: every repository is exported, even one annotated not to be.
 */
@SpringBootApplication
class DataRestAllApp {
}

class Tenant {

    private Long id;

    public Long getId() {
        return id;
    }
}

class Plan {

    private Long id;

    public Long getId() {
        return id;
    }
}

interface TenantRepository extends CrudRepository<Tenant, Long> {
}

@RepositoryRestResource(exported = false)
interface PlanRepository extends CrudRepository<Plan, Long> {
}
