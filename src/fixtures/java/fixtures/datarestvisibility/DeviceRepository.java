package fixtures.datarestvisibility;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(exported = false)
public interface DeviceRepository extends CrudRepository<Device, Long> {
}
