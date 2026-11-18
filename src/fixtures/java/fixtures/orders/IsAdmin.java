package fixtures.orders;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * A meta-annotation: Spring treats {@code @IsAdmin} as {@code @PreAuthorize("hasRole('ADMIN')")}.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.METHOD, ElementType.TYPE })
@PreAuthorize("hasRole('ADMIN')")
@interface IsAdmin {
}
