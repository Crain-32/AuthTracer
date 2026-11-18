package fixtures.scannedbeans.extra;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Outside the component scan, named in META-INF/spring.factories: a bean.
 */
@RestController
class FactoryController {

    @GetMapping("/factory/items")
    String items() {
        return "factory";
    }
}

/**
 * Outside the component scan, named in META-INF/spring/...AutoConfiguration.imports: a bean.
 */
@RestController
class ImportsController {

    @GetMapping("/imports/items")
    String items() {
        return "imports";
    }
}
