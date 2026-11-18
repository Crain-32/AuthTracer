package fixtures.dispatch;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A call on an interface two beans implement runs one of them (here, by profile): it is as open as the more open.
 */
@Configuration
@EnableMethodSecurity
class DispatchApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
        return http.build();
    }

    /**
     * The bean is the class the method creates, not every Notifier.
     */
    @Bean
    Notifier notifier() {
        return new EmailNotifier();
    }
}

interface Accounts {

    String find(long id);
}

@Service
@Profile("secured")
class CheckedAccounts implements Accounts {

    @PreAuthorize("hasRole('ADMIN')")
    public String find(long id) {
        return "account";
    }
}

@Service
@Profile("open")
class OpenAccounts implements Accounts {

    public String find(long id) {
        return "account";
    }
}

interface Reports {

    String report();
}

@Service
@Profile("managers")
class ManagerReports implements Reports {

    @PreAuthorize("hasRole('MANAGER')")
    public String report() {
        return "report";
    }
}

@Service
@Profile("auditors")
class AuditReports implements Reports {

    @PreAuthorize("hasRole('AUDITOR')")
    public String report() {
        return "report";
    }
}

/**
 * Both beans override export with the check: the base method runs for neither.
 */
abstract class Exporter {

    public String export(long id) {
        return "";
    }
}

@Component
class CsvExporter extends Exporter {

    @Override
    @PreAuthorize("hasRole('FINANCE')")
    public String export(long id) {
        return "csv";
    }
}

@Component
class PdfExporter extends Exporter {

    @Override
    @PreAuthorize("hasRole('FINANCE')")
    public String export(long id) {
        return "pdf";
    }
}

interface Notifier {

    String send(long id);
}

class EmailNotifier implements Notifier {

    @PreAuthorize("hasRole('MAILER')")
    public String send(long id) {
        return "sent";
    }
}

/**
 * Not a bean: nothing creates it.
 */
class SmsNotifier implements Notifier {

    public String send(long id) {
        return "sent";
    }
}

/**
 * As OpenAPI Generator writes a delegate: the default answers 501 until the application's bean overrides it.
 */
interface UsersApiDelegate {

    default String user(long id) {
        return "501";
    }
}

@Service
class UsersApiDelegateImpl implements UsersApiDelegate {

    @Override
    @PreAuthorize("hasRole('USERS')")
    public String user(long id) {
        return "user";
    }
}

interface Ledger {

    String entry(long id);
}

/**
 * A caching decorator over the checked ledger: its call to the delegate comes back to it only by recursion.
 */
@Service
@Primary
class CachingLedger implements Ledger {

    private final Ledger delegate;

    CachingLedger(@Qualifier("dbLedger") Ledger delegate) {
        this.delegate = delegate;
    }

    public String entry(long id) {
        return delegate.entry(id);
    }
}

@Service("dbLedger")
class DbLedger implements Ledger {

    @PreAuthorize("hasRole('LEDGER')")
    public String entry(long id) {
        return "entry";
    }
}

@Service
class Checks {

    @PreAuthorize("hasRole('QUERY')")
    public String query() {
        return "checked";
    }

    @PreAuthorize("hasRole('AUDIT')")
    public String audit(long id) {
        return "audited";
    }
}

/**
 * A generic return: javac adds a bridge, Object run(), that calls the real method.
 */
interface Query<R> {

    R run();
}

@Service
class AccountQuery implements Query<String> {

    private final Checks checks;

    AccountQuery(Checks checks) {
        this.checks = checks;
    }

    @Override
    public String run() {
        return checks.query();
    }
}

interface Auditing {

    Checks checks();

    default String audited(long id) {
        return checks().audit(id);
    }
}

/**
 * Inherits audited from its interface: javac names ReportService in the call.
 */
@Service
class ReportService implements Auditing {

    private final Checks checks;

    ReportService(Checks checks) {
        this.checks = checks;
    }

    @Override
    public Checks checks() {
        return checks;
    }
}

@RestController
class DispatchController {

    private final Accounts accounts;
    private final Reports reports;
    private final Exporter exporter;
    private final Notifier notifier;
    private final UsersApiDelegate users;
    private final Ledger ledger;
    private final Query<String> query;
    private final ReportService reportService;

    DispatchController(Accounts accounts, Reports reports, Exporter exporter, Notifier notifier,
            UsersApiDelegate users, Ledger ledger, Query<String> query, ReportService reportService) {
        this.accounts = accounts;
        this.reports = reports;
        this.exporter = exporter;
        this.notifier = notifier;
        this.users = users;
        this.ledger = ledger;
        this.query = query;
        this.reportService = reportService;
    }

    @GetMapping("/exports/{id}")
    String export(@PathVariable long id) {
        return exporter.export(id);
    }

    @GetMapping("/notifications/{id}")
    String notify(@PathVariable long id) {
        return notifier.send(id);
    }

    @GetMapping("/users/{id}")
    String user(@PathVariable long id) {
        return users.user(id);
    }

    @GetMapping("/ledger/{id}")
    String entry(@PathVariable long id) {
        return ledger.entry(id);
    }

    @GetMapping("/query")
    String query() {
        return query.run();
    }

    @GetMapping("/audits/{id}")
    String audit(@PathVariable long id) {
        return reportService.audited(id);
    }

    @GetMapping("/accounts/{id}")
    String account(@PathVariable long id) {
        return accounts.find(id);
    }

    @GetMapping("/reports")
    String report() {
        return reports.report();
    }
}
