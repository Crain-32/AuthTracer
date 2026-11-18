package fixtures.mappingparams;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two handlers for one path, told apart by a request parameter (as the Spring Authorization Server's users-resource
 * sample does): each is its own endpoint, with its own checks.
 */
@Configuration
@EnableMethodSecurity
class MappingParamsConfig {
}

@RestController
class MessagesController {

    @GetMapping(value = "/user/messages", params = "use_case=delegation")
    @PreAuthorize("hasAuthority('SCOPE_delegate')")
    String delegation() {
        return "delegation";
    }

    @GetMapping(value = "/user/messages", params = "use_case=impersonation")
    @PreAuthorize("hasAuthority('SCOPE_impersonate')")
    String impersonation() {
        return "impersonation";
    }
}
