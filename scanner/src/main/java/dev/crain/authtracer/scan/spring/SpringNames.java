package dev.crain.authtracer.scan.spring;

import java.util.List;
import java.util.Map;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Fully qualified names of the Spring types the scanner recognizes.
 */
@Supports(Feature.APPLICATION_GRAPH)
final class SpringNames {

    private SpringNames() {
    }

    static final String COMPONENT = "org.springframework.stereotype.Component";
    static final String CONTROLLER = "org.springframework.stereotype.Controller";
    static final String BEAN = "org.springframework.context.annotation.Bean";
    static final String VALUE = "org.springframework.beans.factory.annotation.Value";
    /**
     * Spring Boot's auto-configuration, on with {@code @SpringBootApplication}.
     */
    static final String ENABLE_AUTO_CONFIGURATION = "org.springframework.boot.autoconfigure.EnableAutoConfiguration";

    static final String REQUEST_MAPPING = "org.springframework.web.bind.annotation.RequestMapping";
    static final Map<String, String> MAPPING_METHODS = Map.of(
            "org.springframework.web.bind.annotation.GetMapping", "GET",
            "org.springframework.web.bind.annotation.PostMapping", "POST",
            "org.springframework.web.bind.annotation.PutMapping", "PUT",
            "org.springframework.web.bind.annotation.DeleteMapping", "DELETE",
            "org.springframework.web.bind.annotation.PatchMapping", "PATCH");

    static final String ENABLE_METHOD_SECURITY =
            "org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity";
    static final String ENABLE_GLOBAL_METHOD_SECURITY =
            "org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity";
    static final String ENABLE_REACTIVE_METHOD_SECURITY =
            "org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity";

    static final String PRE_AUTHORIZE = "org.springframework.security.access.prepost.PreAuthorize";
    static final String POST_AUTHORIZE = "org.springframework.security.access.prepost.PostAuthorize";
    static final String PRE_FILTER = "org.springframework.security.access.prepost.PreFilter";
    static final String POST_FILTER = "org.springframework.security.access.prepost.PostFilter";
    static final String SECURED = "org.springframework.security.access.annotation.Secured";
    static final String ROLES_ALLOWED = "jakarta.annotation.security.RolesAllowed";
    static final String PERMIT_ALL = "jakarta.annotation.security.PermitAll";
    static final String DENY_ALL = "jakarta.annotation.security.DenyAll";

    static final List<String> PRE_POST = List.of(PRE_AUTHORIZE, POST_AUTHORIZE, PRE_FILTER, POST_FILTER);
    static final List<String> JSR_250 = List.of(ROLES_ALLOWED, PERMIT_ALL, DENY_ALL);
    static final List<String> METHOD_SECURITY = List.of(PRE_AUTHORIZE, POST_AUTHORIZE, PRE_FILTER, POST_FILTER,
            SECURED, ROLES_ALLOWED, PERMIT_ALL, DENY_ALL);

    static final String AUTHORIZE_RETURN_OBJECT =
            "org.springframework.security.authorization.method.AuthorizeReturnObject";
    static final String HANDLE_AUTHORIZATION_DENIED =
            "org.springframework.security.authorization.method.HandleAuthorizationDenied";
    static final String NULL_RETURNING_HANDLER =
            "org.springframework.security.authorization.method.NullReturningMethodAuthorizationDeniedHandler";

    static final String REST_CLIENT = "org.springframework.web.client.RestClient";
    static final String REST_CLIENT_BUILDER = "org.springframework.web.client.RestClient$Builder";

    static final String RESOURCE_SERVER_CONFIGURER =
            "org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer";
    static final String HTTP_SECURITY = "org.springframework.security.config.annotation.web.builders.HttpSecurity";
}
