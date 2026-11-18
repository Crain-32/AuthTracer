package fixtures.webfilterauth;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Decision 0071 on WebFlux: a WebFilter that writes an Authentication into the Reactor context from a header.
 */
@SpringBootApplication
class WebFilterAuthApp {
}

@Configuration
@EnableWebFluxSecurity
class WebFilterAuthChain {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().hasRole("SERVICE"))
                .addFilterAt(new ServiceWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}

class ServiceWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String service = exchange.getRequest().getHeaders().getFirst("X-Service");
        if (service == null) {
            return chain.filter(exchange);
        }
        return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                new UsernamePasswordAuthenticationToken(service, null,
                        AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_SERVICE,ROLE_INTERNAL"))));
    }
}

@RestController
class ServiceController {

    @GetMapping("/internal")
    Mono<String> internal() {
        return Mono.just("internal");
    }
}
