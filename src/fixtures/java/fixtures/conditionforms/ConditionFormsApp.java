package fixtures.conditionforms;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnNotWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * Decision 0111: the conditions AuthTracer decides from the classpath, the web stack and the configuration
 * (application.properties: prod active, its group adds cloud), and one it can't.
 */
@RestController
@ConditionalOnClass(name = "com.example.NotThere")
class MissingClassController {

    @GetMapping("/forms/missing-class")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnClass(DispatcherServlet.class)
class PresentClassController {

    @GetMapping("/forms/present-class")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnMissingClass("org.springframework.web.servlet.DispatcherServlet")
class NoDispatcherController {

    @GetMapping("/forms/no-dispatcher")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnMissingClass("com.example.NotThere")
class NoMissingController {

    @GetMapping("/forms/no-missing")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
class ReactiveOnlyController {

    @GetMapping("/forms/reactive-only")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnWebApplication
class AnyWebController {

    @GetMapping("/forms/any-web")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnNotWebApplication
class NotWebController {

    @GetMapping("/forms/not-web")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnBean(name = "auditTrail")
class OnBeanController {

    @GetMapping("/forms/on-bean")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnBooleanProperty("app.flag")
class FlagController {

    @GetMapping("/forms/flag")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnBooleanProperty(name = "app.flag", havingValue = false)
class NoFlagController {

    @GetMapping("/forms/no-flag")
    String get() {
        return "";
    }
}

/**
 * Both must hold: app.mode is lenient.
 */
@RestController
@ConditionalOnProperty(name = "app.mode", havingValue = "strict")
@ConditionalOnProperty(name = "app.flag")
class StrictController {

    @GetMapping("/forms/strict")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnProperty(name = "app.off")
class OffController {

    @GetMapping("/forms/off")
    String get() {
        return "";
    }
}

@RestController
@ConditionalOnProperty(name = "app.unset", matchIfMissing = true)
class UnsetController {

    @GetMapping("/forms/unset")
    String get() {
        return "";
    }
}

/**
 * The prod profile's group adds cloud.
 */
@RestController
@Profile("cloud & prod")
class CloudController {

    @GetMapping("/forms/cloud")
    String get() {
        return "";
    }
}
