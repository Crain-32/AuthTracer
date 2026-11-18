package fixtures.credentialgroups;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.support.OAuth2RestClientHttpServiceGroupConfigurer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * Spring Security's group configurer, as its reference documents it: every HTTP service group's client gets an
 * OAuth2 client token.
 */
@Configuration
@ImportHttpServices(group = "partner", types = PartnerApi.class)
class ClientsConfig {

    @Bean
    OAuth2RestClientHttpServiceGroupConfigurer securityConfigurer(OAuth2AuthorizedClientManager manager) {
        return OAuth2RestClientHttpServiceGroupConfigurer.from(manager);
    }
}

interface PartnerApi {

    @GetExchange("/partner/orders")
    String orders();
}

@RestController
class PartnerController {

    private final PartnerApi partner;

    PartnerController(PartnerApi partner) {
        this.partner = partner;
    }

    @GetMapping("/orders")
    String orders() {
        return partner.orders();
    }
}
