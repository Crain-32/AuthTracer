package fixtures.jaxrsroles;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.stereotype.Component;

/**
 * Jersey checks @RolesAllowed with isUserInRole: the GrantedAuthorityDefaults prefix (none here), and no hierarchy.
 */
@SpringBootApplication
class JaxRsRolesApp {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("admin > user");
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("");
    }
}

@Component
@ApplicationPath("/api")
class JerseyConfig extends ResourceConfig {

    JerseyConfig() {
        register(ProfileResource.class);
        register(RolesAllowedDynamicFeature.class);
    }
}

@Component
@Path("/profile")
class ProfileResource {

    @GET
    @RolesAllowed("user")
    public String profile() {
        return "me";
    }
}
