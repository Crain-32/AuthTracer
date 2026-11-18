package fixtures.datarestimport;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * What every repository of the application extends: not a repository of its own.
 */
@NoRepositoryBean
public interface BaseRepository<T extends AuditedEntity, ID> extends CrudRepository<T, ID> {
}
