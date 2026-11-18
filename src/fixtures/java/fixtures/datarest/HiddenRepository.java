package fixtures.datarest;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(exported = false)
public interface HiddenRepository extends CrudRepository<Secret, Long> {
}
