package fixtures.jsonnaming;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * Each of Jackson's naming strategies, on names with acronyms and a leading underscore.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
record SnakeView(String myHTTPServer, String _id, String a_B) {
}

@JsonNaming(PropertyNamingStrategies.UpperSnakeCaseStrategy.class)
record UpperSnakeView(String myHTTPServer, String homeURL) {
}

@JsonNaming(PropertyNamingStrategies.KebabCaseStrategy.class)
record KebabView(String myHTTPServer, String homeURL, String a1B, String URL) {
}

@JsonNaming(PropertyNamingStrategies.LowerDotCaseStrategy.class)
record DotView(String myHTTPServer, String firstName) {
}

@JsonNaming(PropertyNamingStrategies.LowerCaseStrategy.class)
record LowerView(String myHTTPServer) {
}

@JsonNaming(PropertyNamingStrategies.UpperCamelCaseStrategy.class)
record UpperCamelView(String myHTTPServer, String x) {
}

@JsonNaming(PropertyNamingStrategies.LowerCamelCaseStrategy.class)
record LowerCamelView(String myHTTPServer) {
}

@RestController
class NamingController {

    @GetMapping("/snake")
    SnakeView snake() {
        return new SnakeView("", "", "");
    }

    @GetMapping("/upper-snake")
    UpperSnakeView upperSnake() {
        return new UpperSnakeView("", "");
    }

    @GetMapping("/kebab")
    KebabView kebab() {
        return new KebabView("", "", "", "");
    }

    @GetMapping("/dot")
    DotView dot() {
        return new DotView("", "");
    }

    @GetMapping("/lower")
    LowerView lower() {
        return new LowerView("");
    }

    @GetMapping("/upper-camel")
    UpperCamelView upperCamel() {
        return new UpperCamelView("", "");
    }

    @GetMapping("/lower-camel")
    LowerCamelView lowerCamel() {
        return new LowerCamelView("");
    }
}
