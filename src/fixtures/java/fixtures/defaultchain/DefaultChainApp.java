package fixtures.defaultchain;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Plain Spring (no Boot): @EnableWebSecurity and no SecurityFilterChain bean.
 */
@Configuration
@EnableWebSecurity
class DefaultChainApp {
}

@RestController
class HomeController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
