package fixtures.scanannotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Decision 0111: the application's own annotation carries @SpringBootApplication, whose scan roots it may set
 * through @AliasFor: AuthTracer doesn't tell which components the scan finds.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootApplication
@interface ServiceApplication {
}

@ServiceApplication
class ScanAnnotationApp {
}
