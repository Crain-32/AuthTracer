package fixtures.pointcutforms.billing;

import fixtures.pointcutforms.AdminOnly;
import org.springframework.stereotype.Service;

@Service
public class InvoiceService {

    public String list() {
        return "invoices";
    }

    @AdminOnly
    public void purge() {
    }
}
