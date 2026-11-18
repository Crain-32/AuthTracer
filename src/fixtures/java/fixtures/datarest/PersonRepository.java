package fixtures.datarest;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.security.access.prepost.PreAuthorize;

public interface PersonRepository extends CrudRepository<Person, Long> {

    @Override
    @PreAuthorize("hasRole('ADMIN')")
    <S extends Person> S save(S person);

    @Override
    @RestResource(exported = false)
    void deleteById(Long id);

    List<Person> findByName(@Param("name") String name);
}
