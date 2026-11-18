package fixtures.fields;

import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CardController {

    private final AuthorizationProxyFactory proxyFactory;

    CardController(AuthorizationProxyFactory proxyFactory) {
        this.proxyFactory = proxyFactory;
    }

    @GetMapping("/cards/proxied")
    String proxied() {
        Card card = (Card) proxyFactory.proxy(new Card("4111"));
        return card.getNumber();
    }

    @GetMapping("/cards/raw")
    String raw() {
        return new Card("4111").getNumber();
    }
}
