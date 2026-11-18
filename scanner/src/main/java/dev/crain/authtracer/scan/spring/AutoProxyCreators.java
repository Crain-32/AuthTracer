package dev.crain.authtracer.scan.spring;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.ScanContext;

/**
 * Decision 0092: the auto-proxy creators that apply advisor beans to the application's beans. Spring Boot 4.1.1's
 * {@code AopAutoConfiguration} registers one, unless {@code spring.aop.auto=false}
 * ({@code @ConditionalOnBooleanProperty(name = "spring.aop.auto", matchIfMissing = true)}): an AspectJ one, which
 * applies every advisor, when AspectJ's weaver is on the classpath, else one for the infrastructure role's only
 * ({@code ClassProxyingConfiguration}). {@code @EnableAspectJAutoProxy} registers the AspectJ one too.
 */
@Supports(Feature.METHOD_SECURITY)
final class AutoProxyCreators {

    private static final String ENABLE_ASPECTJ = "org.springframework.context.annotation.EnableAspectJAutoProxy";
    private static final String WEAVER = "org.aspectj.weaver.Advice";

    private AutoProxyCreators() {
    }

    /**
     * Whether Spring Boot registers its auto-proxy creator.
     */
    static boolean boot(ScanContext context) {
        return context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION) && !context.properties()
                .get("spring.aop.auto").map(String::trim).filter("false"::equalsIgnoreCase).isPresent();
    }

    /**
     * Why Spring Boot's auto-proxy creator isn't there to apply an advisor, for a finding: empty unless Boot turns
     * it off.
     */
    static String bootOff(ScanContext context) {
        return context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION) && !boot(context)
                ? ", and spring.aop.auto=false turns Spring Boot's off" : "";
    }

    /**
     * Whether an AspectJ auto-proxy creator applies every advisor bean, whatever its role.
     */
    static boolean aspectJ(ScanContext context) {
        return context.anyClassAnnotated(ENABLE_ASPECTJ) || boot(context) && context.findClass(WEAVER).isPresent();
    }
}
