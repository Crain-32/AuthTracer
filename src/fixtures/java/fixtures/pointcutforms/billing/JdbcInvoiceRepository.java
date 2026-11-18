package fixtures.pointcutforms.billing;

import org.springframework.stereotype.Repository;

@Repository
public class JdbcInvoiceRepository implements InvoiceRepository {

    @Override
    public String load(long id) {
        return "invoice";
    }

    /**
     * Not on the interface.
     */
    public int count() {
        return 0;
    }
}
