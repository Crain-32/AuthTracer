package fixtures.pointcutforms;

import fixtures.pointcutforms.billing.InvoiceService;
import fixtures.pointcutforms.billing.JdbcInvoiceRepository;
import fixtures.pointcutforms.ledger.Ledger;
import fixtures.pointcutforms.reports.Charts;
import fixtures.pointcutforms.reports.Dashboard;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class PointcutFormsController {

    private final InvoiceService invoices;
    private final JdbcInvoiceRepository repository;
    private final Archive archive;
    private final Ledger ledger;
    private final Exporter exporter;
    private final Statements statements;
    private final Dashboard dashboard;
    private final Charts charts;
    private final Drafts drafts;

    PointcutFormsController(InvoiceService invoices, JdbcInvoiceRepository repository, Archive archive, Ledger ledger,
            Exporter exporter, Statements statements, Dashboard dashboard, Charts charts, Drafts drafts) {
        this.invoices = invoices;
        this.repository = repository;
        this.archive = archive;
        this.ledger = ledger;
        this.exporter = exporter;
        this.statements = statements;
        this.dashboard = dashboard;
        this.charts = charts;
        this.drafts = drafts;
    }

    @GetMapping("/invoices")
    String invoices() {
        return invoices.list();
    }

    @PostMapping("/invoices/purge")
    void purge() {
        invoices.purge();
    }

    @GetMapping("/invoices/{id}")
    String invoice(@PathVariable long id) {
        return repository.load(id);
    }

    @GetMapping("/invoices/count")
    int count() {
        return repository.count();
    }

    @GetMapping("/archive")
    String archive() {
        return archive.fetch();
    }

    @GetMapping("/ledger")
    String ledger() {
        return ledger.entries();
    }

    @GetMapping("/ledger/rates")
    String rates() {
        return ledger.rates();
    }

    @GetMapping("/exports/{id}")
    String export(@PathVariable long id) {
        return exporter.findById(id);
    }

    @GetMapping("/exports/total")
    int total(@RequestParam long account) {
        return exporter.findTotal(account);
    }

    @GetMapping("/exports/draft")
    String draft(@RequestParam long id) {
        return exporter.findDraft(id);
    }

    @GetMapping("/exports/range")
    String range(@RequestParam long from, @RequestParam long to) {
        return exporter.findBetween(from, to);
    }

    @GetMapping("/exports/by-name")
    String byName(@RequestParam String name) {
        return exporter.findByName(name);
    }

    @GetMapping("/exports/yearly")
    String yearly(@RequestParam String format, @RequestParam int year) {
        return exporter.export(format, year);
    }

    @GetMapping("/exports/all")
    String all() {
        return exporter.exportAll();
    }

    @GetMapping("/statements/monthly")
    String monthly(@RequestParam String account, @RequestParam int month) {
        return statements.monthly(account, month);
    }

    @GetMapping("/statements/yearly")
    String yearlyStatement(@RequestParam long account) {
        return statements.yearly(account);
    }

    @GetMapping("/dashboard")
    String dashboard() {
        return dashboard.summary();
    }

    @GetMapping("/dashboard/health")
    String health() {
        return dashboard.health();
    }

    @GetMapping("/charts")
    String charts() {
        return charts.render();
    }

    @PostMapping("/drafts/open")
    String open() {
        return drafts.open();
    }

    @PostMapping("/drafts/close")
    String close() {
        return drafts.close();
    }
}

@Component
@Audited
class Archive {

    public String fetch() {
        return "archived";
    }
}

@Component
class Exporter {

    public String findById(long id) {
        return "export";
    }

    public int findTotal(long account) {
        return 0;
    }

    String findDraft(long id) {
        return "draft";
    }

    public String findBetween(long from, long to) {
        return "exports";
    }

    public String findByName(String name) {
        return "export";
    }

    public String export(String format, int year) {
        return "export";
    }

    public String exportAll() {
        return "exports";
    }
}

@Component
class Statements {

    public String monthly(String account, int month) {
        return "monthly";
    }

    public String yearly(long account) {
        return "yearly";
    }
}

@Component
class Drafts {

    protected String open() {
        return "opened";
    }

    public String close() {
        return "closed";
    }
}
