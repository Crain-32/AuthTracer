package fixtures.pointcutforms.billing;

/**
 * The contract an {@code execution(..)} pattern names: it matches the implementation's methods declared here.
 */
public interface InvoiceRepository {

    String load(long id);
}
