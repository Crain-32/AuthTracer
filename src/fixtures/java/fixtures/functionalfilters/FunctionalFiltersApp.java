package fixtures.functionalfilters;

import static org.springframework.web.servlet.function.RequestPredicates.GET;
import static org.springframework.web.servlet.function.RouterFunctions.route;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Filters of functional routes run before the handler: a builder's filter(..) and before(..) for every route it
 * builds, RouterFunction#filter(..) for every route of the function. Here they check the caller: method security on a
 * bean the filter calls, and a filter class that reads the caller's authorities itself.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class FunctionalFiltersApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()).authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    RouterFunction<ServerResponse> reports(Auditors auditors) {
        return route().GET("/reports", request -> ServerResponse.ok().body("reports"))
                .before(request -> {
                    auditors.check();
                    return request;
                })
                .GET("/reports/latest", request -> ServerResponse.ok().body("latest"))
                .build();
    }

    @Bean
    RouterFunction<ServerResponse> exports() {
        return route(GET("/exports"), request -> ServerResponse.ok().body("exports")).filter(new TellersOnly());
    }

    @Bean
    RouterFunction<ServerResponse> imports(HandlerFilterFunction<ServerResponse, ServerResponse> logging) {
        return route().POST("/imports", request -> ServerResponse.ok().body("imported")).filter(logging).build();
    }

    @Bean
    HandlerFilterFunction<ServerResponse, ServerResponse> logging() {
        return (request, next) -> next.handle(request);
    }
}

@Component
class Auditors {

    @PreAuthorize("hasRole('AUDITOR')")
    void check() {
    }
}

class TellersOnly implements HandlerFilterFunction<ServerResponse, ServerResponse> {

    @Override
    public ServerResponse filter(ServerRequest request, HandlerFunction<ServerResponse> next) throws Exception {
        Authentication caller = SecurityContextHolder.getContext().getAuthentication();
        if (caller.getAuthorities().stream().noneMatch(authority -> authority.getAuthority().equals("ROLE_TELLER"))) {
            return ServerResponse.status(HttpStatus.FORBIDDEN).build();
        }
        return next.handle(request);
    }
}
