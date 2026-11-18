package fixtures.mappingforms;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;

import org.springframework.core.annotation.AliasFor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Mappings in the other forms controllers use: Spring 3's @RequestMapping with its method, the root path, one
 * handler at a path with and without its trailing slash, composed annotations whose path is an @AliasFor (naming
 * the mapping's attribute, or written as Spring's own @PostMapping is, by the element's name; one aliasing
 * another meta-annotation too) and one with a fixed path (only @RequestMapping can be a meta-annotation: @GetMapping
 * and the others target methods alone), and an abstract base controller with an abstract and a
 * static method.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping(method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
@interface GetJson {

    @AliasFor(annotation = RequestMapping.class, attribute = "path")
    String[] value() default {};
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
@interface PostJson {

    @AliasFor(annotation = RequestMapping.class)
    String name() default "";

    @AliasFor(annotation = RequestMapping.class)
    String[] value() default {};

    @AliasFor(annotation = RequestMapping.class)
    String[] path() default {};
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping(method = RequestMethod.POST)
@ResponseStatus(HttpStatus.CREATED)
@interface Create {

    @AliasFor(annotation = RequestMapping.class)
    String[] value() default {};

    @AliasFor(annotation = ResponseStatus.class, attribute = "reason")
    String reason() default "";
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@RequestMapping(path = "/health", method = RequestMethod.GET)
@interface HealthCheck {
}

@RestController
class HomeController {

    @GetMapping("/")
    String home() {
        return "home";
    }

    @RequestMapping(value = "/legacy/orders", method = RequestMethod.POST)
    String create() {
        return "created";
    }

    @RequestMapping(path = "/legacy/orders/{id}", method = {RequestMethod.PUT, RequestMethod.PATCH})
    String update(@PathVariable("id") long id) {
        return "updated";
    }

    @GetJson("/api/orders")
    List<String> orders() {
        return List.of();
    }

    @PostJson(name = "placeOrder", path = "/api/orders")
    String place() {
        return "placed";
    }

    @PostJson("/api/orders/{id}/cancel")
    String cancel(@PathVariable("id") long id) {
        return "cancelled";
    }

    @Create(value = "/api/invoices", reason = "Invoice created")
    String invoice() {
        return "created";
    }

    @HealthCheck
    String health() {
        return "up";
    }
}

abstract class CatalogController {

    @GetMapping({"", "/"})
    List<String> list() {
        return names(items());
    }

    protected abstract List<String> items();

    static List<String> names(List<String> items) {
        return items;
    }
}

@RestController
@RequestMapping("/catalog")
class BookCatalogController extends CatalogController {

    @Override
    protected List<String> items() {
        return List.of("Dune");
    }
}
