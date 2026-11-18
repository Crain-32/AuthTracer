package fixtures.jaxrs;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

/**
 * Decision 0052: JAX-RS resources registered with Jersey under /api, behind the filter chain.
 */
@SpringBootApplication
@EnableMethodSecurity
class JaxRsApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@Component
@ApplicationPath("/api")
class JerseyConfig extends ResourceConfig {

    JerseyConfig() {
        register(OrderResource.class);
        registerClasses(PublicResource.class, AuditResource.class);
        // Jersey enforces @RolesAllowed itself.
        register(RolesAllowedDynamicFeature.class);
    }
}

record Order(long id, String sku) {
}

@Component
@Path("/orders")
class OrderResource {

    @GET
    @Path("/{id: [0-9]{1,9}}")
    public Order order(@PathParam("id") long id) {
        return new Order(id, "sku");
    }

    @POST
    @PreAuthorize("hasRole('CLERK')")
    public Response create(Order order) {
        return Response.ok().build();
    }
}

@Component
@Path("/public")
class PublicResource {

    @GET
    @Path("/status")
    public String status() {
        return "up";
    }
}

@Component
@Path("/audit")
@RolesAllowed("AUDITOR")
class AuditResource {

    @GET
    public String trail() {
        return "trail";
    }

    @GET
    @Path("/purge")
    @DenyAll
    public String purge() {
        return "purged";
    }
}

/**
 * Not registered: Jersey doesn't serve it.
 */
@Component
@Path("/hidden")
class HiddenResource {

    @GET
    public String hidden() {
        return "hidden";
    }
}
