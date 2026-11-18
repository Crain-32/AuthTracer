package fixtures.relay;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class RelayController {

    private final WebClientRelay webClient;
    private final OAuth2Calls oauth2;
    private final StaticCalls fixed;
    private final PlainCalls plain;
    private final CustomRelay custom;
    private final LambdaRelay lambda;
    private final LibraryCalls library;
    private final PartnerApi partner;
    private final RegistrationCalls registrations;

    RelayController(WebClientRelay webClient, OAuth2Calls oauth2, StaticCalls fixed, PlainCalls plain,
            CustomRelay custom, LambdaRelay lambda, LibraryCalls library, PartnerApi partner,
            RegistrationCalls registrations) {
        this.registrations = registrations;
        this.webClient = webClient;
        this.oauth2 = oauth2;
        this.fixed = fixed;
        this.plain = plain;
        this.custom = custom;
        this.lambda = lambda;
        this.library = library;
        this.partner = partner;
    }

    @GetMapping("/all")
    String all() {
        return webClient.call() + oauth2.call() + fixed.call() + plain.call() + custom.call() + lambda.call()
                + library.call() + partner.data() + registrations.asUser() + registrations.asService();
    }
}
