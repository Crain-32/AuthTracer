package fixtures.datarestvisibility;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

/**
 * spring.data.rest.detection-strategy=visibility: public repositories are exported, whatever their annotation says
 * (Spring Data REST 5.1.1's VISIBILITY reads only the interface's modifiers).
 */
@SpringBootApplication
class DataRestVisibilityApp {
}

class Device {

    private Long id;

    public Long getId() {
        return id;
    }
}

class Firmware {

    private Long id;

    public Long getId() {
        return id;
    }
}

@RepositoryRestResource
interface FirmwareRepository extends CrudRepository<Firmware, Long> {
}
