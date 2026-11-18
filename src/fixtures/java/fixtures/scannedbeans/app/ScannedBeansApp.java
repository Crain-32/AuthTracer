package fixtures.scannedbeans.app;

import fixtures.scannedbeans.extra.ImportedSecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0111: the component scan starts at this package; the extra package's classes are beans only when
 * something imports them.
 */
@SpringBootApplication
@Import(ImportedSecurity.class)
public class ScannedBeansApp {

    public static void main(String[] args) {
        SpringApplication.run(ScannedBeansApp.class, args);
    }
}

@RestController
class ItemsController {

    @GetMapping("/items")
    String items() {
        return "items";
    }
}
