package fixtures.jaxrspackages;

import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Decision 0052: Jersey configured by a ResourceConfig bean that scans a package for its resources, at
 * spring.jersey.application-path, with Jersey's @RolesAllowed feature.
 */
@SpringBootApplication
class JaxRsPackagesApp {

    @Bean
    ResourceConfig jerseyConfig() {
        ResourceConfig config = new ResourceConfig();
        config.packages("fixtures.jaxrspackages.api");
        config.register(RolesAllowedDynamicFeature.class);
        return config;
    }
}
