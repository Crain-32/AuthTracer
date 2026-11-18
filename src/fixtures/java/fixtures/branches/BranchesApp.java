package fixtures.branches;

import java.util.NoSuchElementException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableMethodSecurity
class BranchesApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        return http.build();
    }
}

record Doc(long id, String body) {
}

@Component
class DocCache {

    Doc get(long id) {
        return null;
    }
}

@Service
class DocService {

    @PreAuthorize("hasRole('READER')")
    public Doc find(long id) {
        return new Doc(id, "summary");
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Doc full(long id) {
        return new Doc(id, "full");
    }
}

@Component
class Access {

    @PreAuthorize("hasRole('MANAGER')")
    public void requireManager(long id) {
    }
}

@Service
class Archive {

    @PreAuthorize("hasRole('ARCHIVIST')")
    public Doc load(long id) {
        return new Doc(id, "archived");
    }
}

/**
 * Branches of its own, reached on only some ways through the controller.
 */
@Service
class DocViewer {

    private final DocCache cache;
    private final DocService docs;

    DocViewer(DocCache cache, DocService docs) {
        this.cache = cache;
        this.docs = docs;
    }

    Doc view(long id, boolean preview) {
        return preview ? docs.find(id) : docs.full(id);
    }

    /**
     * A preview comes from the cache, unchecked.
     */
    Doc peek(long id, boolean preview) {
        return preview ? cache.get(id) : docs.full(id);
    }
}

@RestController
class BranchController {

    private final DocCache cache;
    private final DocService docs;
    private final Archive archive;
    private final DocViewer viewer;
    private final Access access;

    BranchController(DocCache cache, DocService docs, Archive archive, DocViewer viewer, Access access) {
        this.cache = cache;
        this.docs = docs;
        this.archive = archive;
        this.viewer = viewer;
        this.access = access;
    }

    /**
     * The denial is caught and the request carries on: anyone gets the doc.
     */
    @GetMapping("/swallowed/{id}")
    Doc swallowed(@PathVariable long id) {
        try {
            access.requireManager(id);
        }
        catch (AccessDeniedException ex) {
            // Logged and ignored.
        }
        return new Doc(id, "salary");
    }

    /**
     * The viewer's branches are alternatives too: a reader gets in through its preview.
     */
    @GetMapping("/archived/{id}")
    Doc archived(@PathVariable long id, @RequestParam boolean archived, @RequestParam boolean preview) {
        if (archived) {
            return archive.load(id);
        }
        return viewer.view(id, preview);
    }

    /**
     * The viewer's preview is unchecked, so this is as open as the chain leaves it.
     */
    @GetMapping("/peeked/{id}")
    Doc peeked(@PathVariable long id, @RequestParam boolean archived, @RequestParam boolean preview) {
        if (archived) {
            return archive.load(id);
        }
        return viewer.peek(id, preview);
    }

    /**
     * A cache hit returns without the check.
     */
    @GetMapping("/cached/{id}")
    Doc cached(@PathVariable long id) {
        Doc hit = cache.get(id);
        if (hit != null) {
            return hit;
        }
        return docs.find(id);
    }

    /**
     * Each branch has its own check: the weaker one decides.
     */
    @GetMapping("/either/{id}")
    Doc either(@PathVariable long id, @RequestParam boolean full) {
        return full ? docs.full(id) : docs.find(id);
    }

    /**
     * A guard clause throws; the only return passes the check.
     */
    @GetMapping("/guarded/{id}")
    Doc guarded(@PathVariable long id) {
        if (id < 0) {
            throw new IllegalArgumentException("negative id");
        }
        return docs.find(id);
    }

    /**
     * The catch block runs after find threw, so find's check ran.
     */
    @GetMapping("/fallback/{id}")
    Doc fallback(@PathVariable long id) {
        try {
            return docs.find(id);
        }
        catch (NoSuchElementException ex) {
            return new Doc(id, "");
        }
    }

    /**
     * If/else with separate returns, both checked.
     */
    @GetMapping("/split/{id}")
    Doc split(@PathVariable long id, @RequestParam boolean full) {
        if (full) {
            return docs.full(id);
        }
        return docs.find(id);
    }
}
