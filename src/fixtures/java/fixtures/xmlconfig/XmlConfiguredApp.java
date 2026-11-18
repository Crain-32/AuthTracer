package fixtures.xmlconfig;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configured by WEB-INF/spring/security.xml only.
 */
@RestController
class XmlEndpoints {

    private final Inventory inventory;
    private final Catalog catalog;

    XmlEndpoints(Inventory inventory, Catalog catalog) {
        this.inventory = inventory;
        this.catalog = catalog;
    }

    @GetMapping("/catalog")
    String catalog() {
        return catalog.browse();
    }

    @GetMapping("/api/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/api/items")
    String items() {
        return inventory.list();
    }

    @PostMapping("/api/items")
    String add() {
        return inventory.add();
    }

    @GetMapping("/css/site.css")
    String css() {
        return "css";
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}

/**
 * Method security on an interface; its implementation is a bean defined in XML.
 */
interface Catalog {

    @PreAuthorize("hasRole('BUYER')")
    String browse();
}

class XmlCatalog implements Catalog {

    @Override
    public String browse() {
        return "catalog";
    }
}

@Service
class Inventory {

    @PreAuthorize("hasRole('CLERK')")
    public String list() {
        return "items";
    }

    /** <method-security/> doesn't enable @Secured. */
    @Secured("ROLE_CLERK")
    public String add() {
        return "added";
    }
}
