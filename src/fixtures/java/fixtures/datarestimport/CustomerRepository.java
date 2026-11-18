package fixtures.datarestimport;

import java.util.List;

import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RestResource;

public interface CustomerRepository extends BaseRepository<Customer, Long> {

    @RestResource(path = "by-name", rel = "by-name")
    List<Customer> findByNameContaining(@Param("name") String name);

    default List<Customer> findVip() {
        return findByNameContaining("vip");
    }
}
