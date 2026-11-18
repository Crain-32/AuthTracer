package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.diff.SourceFiles.Location;
import dev.crain.authtracer.graph.CodeRef;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Where a CodeRef is in a project's source, for SARIF and the agent report: the line of the check's annotation, else
 * of the declaration, in Java, Kotlin and Groovy, and in resources.
 */
class SourceFilesTests {

    private static final String REFUNDS = """
            package app;

            /**
             * Refunds.
             */
            @Service
            public class Refunds {

                private final Repository repository;

                public Refunds(Repository repository) {
                    this.repository = repository;
                }

                /**
                 * Refunds an order.
                 */
                @PreAuthorize("hasRole('ADMIN') "
                        + "or hasRole('OPS')")
                public void refund(long id) {
                    if (repository.refunded(id)) {
                        throw notFound(id);
                    }
                    repository.refund(id);
                }

                @PreAuthorize(\"""
                        hasRole('ADMIN')
                        \""")
                @Transactional(
                        readOnly = false,
                        timeout = 5
                )
                public void purge() {
                    repository.purge();
                }

                public void purge(boolean all) {
                    repository.purge();
                }

                public void refund(Map<String, Long> amounts, @Value("${refunds.limit:100}") long limit) {
                    amounts.keySet().forEach(id -> refund(Long.parseLong(id)));
                }

                @PreAuthorize("hasRole('ADMIN')")
                public <T extends Comparable<T>> T save(T entity) {
                    return entity;
                }

                public <T> T save(T entity, boolean flush) {
                    return entity;
                }

                private static ResponseStatusException notFound(long id) {
                    return new ResponseStatusException(HttpStatus.NOT_FOUND);
                }

                static class Policy {
                }
            }
            """;

    private static final String ACCOUNTS = """
            package app;

            public interface Accounts extends Repository<Account, Long> {

                @PreAuthorize("hasRole('ADMIN')")
                List<Account> findAll();

                Account findByIban(String iban);
            }
            """;

    private static final String ORDERS = """
            package app

            @Service
            class Orders {

                @PreAuthorize("hasRole('ADMIN')")
                fun find(vararg ids: Long): List<Order> = listOf()

                fun find(name: String, page: Int = 0): List<Order> = listOf()

                fun <T : Any> save(entity: T): T = entity
            }

            fun ordersOf(customer: String?): List<Order> = listOf()
            """;

    private static final String HANDLERS = """
            package app

            class OrderHandler {

                def handle(String id) {
                    id
                }
            }
            """;

    @TempDir
    Path project;

    private SourceFiles sources;

    @BeforeEach
    void sources() throws IOException {
        write("src/main/java/app/Refunds.java", REFUNDS);
        write("src/main/java/app/Accounts.java", ACCOUNTS);
        write("src/main/java/Main.java", "public class Main {\n}\n");
        write("src/main/kotlin/app/Orders.kt", ORDERS);
        write("src/main/groovy/app/Handlers.groovy", HANDLERS);
        write("src/main/groovy/app/Cleanup.groovy", "println 'cleaning up'\n");
        write("src/main/resources/templates/accounts.html", "<p sec:authorize=\"hasRole('ADMIN')\">\n");
        write("src/main/resources/security.xml", "<http>\n</http>\n");
        // Not the project's source sets: a build's copy of them, a script.
        write("build/src/main/java/app/Generated.java", "class Generated {\n}\n");
        write("scripts/java/app/Tool.java", "class Tool {\n}\n");
        sources = SourceFiles.of(project);
    }

    @Test
    void aCheckIsAtItsAnnotationAboveEveryLineItsArgumentsTake() {
        assertThat(locate("app.Refunds", "refund(long)", "@PreAuthorize"))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "@PreAuthorize(\"hasRole('ADMIN') \""));
        assertThat(locate("app.Refunds", "purge()", "@PreAuthorize"))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "@PreAuthorize(\"\"\""));
        // Not there: the declaration, above which are only its Javadoc and a blank line.
        assertThat(locate("app.Refunds", "refund(long)", "@Secured"))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "public void refund(long id)"));
    }

    @Test
    void aSourceThatIsntUtf8IsReadByteForByte() throws IOException {
        String latin = "package app;\n\n// Café\npublic class Latin {\n\n    public void pay() {\n    }\n}\n";
        Files.writeString(Files.createDirectories(project.resolve("src/main/java/app")).resolve("Latin.java"), latin,
                StandardCharsets.ISO_8859_1);

        assertThat(SourceFiles.of(project).locate(new CodeRef("app.Latin", "pay()", null), null))
                .hasValue(at("src/main/java/app/Latin.java", latin, "public void pay()"));
    }

    @Test
    void aMethodIsAtItsDeclaration() {
        assertThat(locate("app.Refunds", "<init>(app.Repository)", null))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "public Refunds(Repository repository)"));
        // Not where it is called.
        assertThat(locate("app.Refunds", "notFound(long)", null))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "ResponseStatusException notFound(long id)"));
        // Of overloads, the one with the method key's parameters.
        assertThat(locate("app.Refunds", "refund(java.util.Map,long)", null)).hasValue(at(
                "src/main/java/app/Refunds.java", REFUNDS, "public void refund(Map<String, Long> amounts"));
        // Generic: T erases to its bound.
        assertThat(locate("app.Refunds", "save(java.lang.Comparable)", "@PreAuthorize"))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "@PreAuthorize(\"hasRole('ADMIN')\")"));
        assertThat(locate("app.Refunds", "save(java.lang.Object,boolean)", null))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "public <T> T save(T entity, boolean flush)"));
        // A repository's: declared without a body.
        assertThat(locate("app.Accounts", "findAll()", "@PreAuthorize"))
                .hasValue(at("src/main/java/app/Accounts.java", ACCOUNTS, "@PreAuthorize"));
        assertThat(locate("app.Accounts", "findByIban(java.lang.String)", null))
                .hasValue(at("src/main/java/app/Accounts.java", ACCOUNTS, "Account findByIban(String iban);"));
        // What the source doesn't declare, a generated getter: the class.
        assertThat(locate("app.Refunds", "getRepository()", null))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "public class Refunds"));
    }

    @Test
    void kotlinFunctionsAreFoundByTheirParameters() {
        // vararg ids: Long is a long[]: no declaration names it so, and one has one parameter.
        assertThat(locate("app.Orders", "find(long[])", "@PreAuthorize"))
                .hasValue(at("src/main/kotlin/app/Orders.kt", ORDERS, "@PreAuthorize"));
        assertThat(locate("app.Orders", "find(java.lang.String,int)", null))
                .hasValue(at("src/main/kotlin/app/Orders.kt", ORDERS, "fun find(name: String, page: Int = 0)"));
        assertThat(locate("app.Orders", "save(java.lang.Object)", null))
                .hasValue(at("src/main/kotlin/app/Orders.kt", ORDERS, "fun <T : Any> save(entity: T)"));
        // A top-level function is in the file's facade class.
        assertThat(locate("app.OrdersKt", "ordersOf(java.lang.String)", null))
                .hasValue(at("src/main/kotlin/app/Orders.kt", ORDERS, "fun ordersOf("));
    }

    @Test
    void aClassIsInTheFileOfItsOuterClassOrThatDeclaresIt() {
        assertThat(locate("app.Refunds$Policy", null, null))
                .hasValue(at("src/main/java/app/Refunds.java", REFUNDS, "public class Refunds"));
        assertThat(locate("Main", null, null)).hasValue(new Location("src/main/java/Main.java", 1));
        assertThat(locate("app.OrderHandler", "handle(java.lang.String)", null))
                .hasValue(at("src/main/groovy/app/Handlers.groovy", HANDLERS, "def handle(String id)"));
        // A Groovy script declares no class.
        assertThat(locate("app.Cleanup", null, null)).hasValue(new Location("src/main/groovy/app/Cleanup.groovy", 1));
        assertThat(locate("Main", null, "@SpringBootApplication")).hasValue(new Location("src/main/java/Main.java", 1));
        // A line the scan recorded is the line, even past the end of a source that changed since.
        assertThat(sources.locate(CodeRef.ofMethod("app.Refunds", "refund(long)").atLine(22), "@PreAuthorize"))
                .hasValue(new Location("src/main/java/app/Refunds.java", 22));
        assertThat(sources.locate(CodeRef.ofMethod("app.Refunds", "refund(long)").atLine(500), "@PreAuthorize"))
                .hasValue(new Location("src/main/java/app/Refunds.java", 500));
    }

    @Test
    void aResourceIsAtItsPath() {
        assertThat(sources.locate(CodeRef.ofClass("templates/accounts.html").atLine(1), null))
                .hasValue(new Location("src/main/resources/templates/accounts.html", 1));
        assertThat(sources.locate(CodeRef.ofClass("security.xml"), null))
                .hasValue(new Location("src/main/resources/security.xml", 1));
        assertThat(sources.locate(CodeRef.ofClass("templates/missing.html"), null)).isEmpty();
    }

    @Test
    void aProvidedFactIsAtItsLineInTheProjectsFactsFile() throws IOException {
        write("authtracer.yaml", "version: 1\nfacts:\n  - kind: declassify\n    field: app.View.band\n");

        assertThat(SourceFiles.of(project).locate(CodeRef.ofClass("authtracer.yaml").atLine(3), null))
                .hasValue(new Location("authtracer.yaml", 3));
    }

    @Test
    void codeOutsideTheProjectsSourceSetsIsNowhere() {
        assertThat(locate("app.Generated", null, null)).isEmpty();
        assertThat(locate("app.Tool", null, null)).isEmpty();
        assertThat(locate("other.Missing", null, null)).isEmpty();
        assertThat(sources.locate(null, null)).isEmpty();
        // The project's facts file, when it has none.
        assertThat(sources.locate(CodeRef.ofClass("authtracer.yaml"), null)).isEmpty();
    }

    @Test
    void aSourceSetGivenAsTheProjectIsItsOwnRoot() {
        assertThat(SourceFiles.of(project.resolve("src/main/java")).locate(CodeRef.ofClass("app.Accounts"), null))
                .hasValue(at("app/Accounts.java", ACCOUNTS, "public interface Accounts"));
    }

    private Optional<Location> locate(String className, String method, String annotation) {
        return sources.locate(new CodeRef(className, method, null), annotation);
    }

    /**
     * The first line of the file that contains the text.
     */
    private static Location at(String uri, String content, String text) {
        List<String> lines = content.lines().toList();
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).contains(text)) {
                return new Location(uri, i + 1);
            }
        }
        throw new AssertionError("No line contains " + text);
    }

    private void write(String relative, String content) throws IOException {
        Path file = project.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
