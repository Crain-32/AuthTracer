package fixtures.pointcutforms.ledger;

import fixtures.pointcutforms.PublicApi;
import org.springframework.stereotype.Component;

@Component
public class Ledger {

    public String entries() {
        return "entries";
    }

    @PublicApi
    public String rates() {
        return "rates";
    }
}
