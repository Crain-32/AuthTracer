package fixtures.freemarkerviews;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * FreeMarker views (templates/*.ftlh), with Spring Security's taglib through JspTaglibs.
 */
record Account(Long id, String holder, String iban, List<Card> cards) {
}

record Card(String number, String expiry) {
}

@Service
class AccountService {

    Account mine() {
        return new Account(1L, "ann", "DE00", List.of(new Card("4111", "01/30")));
    }
}

@Controller
class AccountController {

    private final AccountService accounts;

    AccountController(AccountService accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/account")
    String account(Model model) {
        model.addAttribute("account", accounts.mine());
        return "account";
    }
}
