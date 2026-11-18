package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ViewTemplatesTests {

    private static final String OWNER_DETAILS = """
            <html th:replace="~{fragments/layout :: layout (~{::body},'owners')}">
            <body>
              <table class="table table-striped" th:object="${owner}">
                <tr><th>Name</th><td><b th:text="*{firstName + ' ' + lastName}"></b></td></tr>
                <tr><td th:text="*{address}"></td></tr>
              </table>
              <a th:href="@{{id}/edit(id=${owner.id})}">Edit Owner</a>
              <br/>
              <table>
                <tr th:each="pet : ${owner.pets}">
                  <td><dd th:text="${pet.name}"></dd>
                  <dd th:text="${#temporals.format(pet.birthDate, 'yyyy-MM-dd')}"></dd>
                  <table><tr th:each="visit : ${pet.visits}"><td th:text="${visit.description}"></td></tr></table>
                  </td>
                </tr>
              </table>
              <div sec:authorize="hasRole('ADMIN')"><span th:text="${owner.getTelephone()}">x</span></div>
              <p>[[${owner.city}]]</p>
            </body>
            </html>
            """;

    @Test
    void theModelPathsATemplateReads() {
        List<String> fragments = new ArrayList<>();
        List<ViewTemplates.Read> reads = ViewTemplates.parse("owners/ownerDetails", OWNER_DETAILS,
                fragments::add);
        assertThat(reads).extracting(ViewTemplates.Read::path).containsOnly("owner.firstName",
                "owner.lastName", "owner.address", "owner.id", "owner.pets", "owner.pets[].name",
                "owner.pets[].birthDate", "owner.pets[].visits", "owner.pets[].visits[].description",
                "owner.telephone", "owner.city");
        assertThat(fragments).containsExactly("fragments/layout");
    }

    @Test
    void bracketsReadPropertiesAndElements() {
        List<ViewTemplates.Read> reads = ViewTemplates.parse("x", """
                <p th:text="${owner['new']} ? 'new' : ${owner.pets[0].name}">x</p>
                <p th:field="*{__${name}__}">x</p>
                <p th:each="i : ${#numbers.sequence(1, totalPages)}" th:text="${i}">x</p>
                """, fragment -> { });
        assertThat(reads).extracting(ViewTemplates.Read::path).containsOnly("owner.new",
                "owner.pets[].name");
    }

    @Test
    void secAuthorizeGuardsWhatIsReadInside() {
        List<ViewTemplates.Read> reads = ViewTemplates.parse("owners/ownerDetails", OWNER_DETAILS,
                fragment -> { });
        assertThat(reads).filteredOn(read -> read.path().equals("owner.telephone")).singleElement()
                .satisfies(read -> {
                    assertThat(read.guards()).containsExactly("hasRole('ADMIN')");
                    assertThat(read.line()).isEqualTo(17);
                });
        assertThat(reads).filteredOn(read -> read.path().equals("owner.city")).singleElement()
                .satisfies(read -> assertThat(read.guards()).isEmpty());
    }

    @Test
    void theDataAttributeFormsSetUpTheirScopeToo() {
        List<ViewTemplates.Read> reads = ViewTemplates.parse("x", """
                <div data-sec-authorize="hasRole('ADMIN')">
                  <ul><li data-th-each="pet : ${owner.pets}" data-th-text="${pet.name}"></li></ul>
                </div>
                """, fragment -> { });
        assertThat(reads).extracting(ViewTemplates.Read::path).containsOnly("owner.pets", "owner.pets[].name");
        assertThat(reads).allSatisfy(read -> assertThat(read.guards()).containsExactly("hasRole('ADMIN')"));
    }

    @Test
    void aJspReadsElJstlAndSpringsTags() {
        List<String> fragments = new ArrayList<>();
        List<ViewTemplates.Read> reads = ViewTemplates.parse("contacts", """
                <%@ include file="/WEB-INF/jsp/include.jsp" %>
                <c:set var="first" value="${contacts[0]}"/>
                <p>${first.name}</p>
                <c:forEach var="contact" items="${contacts}">
                  <td><c:out value="${contact.email}"/></td>
                  <sec:authorize access="hasRole('SUPERVISOR')"><td>${contact.phone}</td></sec:authorize>
                </c:forEach>
                <form:form modelAttribute="contact" action="add.htm">
                  <form:input path="name"/><form:errors path="*"/>
                </form:form>
                <spring:bind path="contact.email"><input value="${status.value}"/></spring:bind>
                <jsp:include page="footer.jsp"/>
                """, fragments::add, ViewTemplates.Dialect.JSP);
        assertThat(reads).extracting(ViewTemplates.Read::path).containsOnly("contacts", "contacts[].name",
                "contacts[].email", "contacts[].phone", "contact.name", "contact.email", "status.value");
        assertThat(reads).filteredOn(read -> read.path().equals("contacts[].phone")).singleElement()
                .satisfies(read -> assertThat(read.guards()).containsExactly("hasRole('SUPERVISOR')"));
        assertThat(fragments).containsExactly("/WEB-INF/jsp/include.jsp", "footer.jsp");
    }

    @Test
    void jstlsBodyFormsAndCountingLoopsDeclareNoModelPaths() {
        List<ViewTemplates.Read> reads = ViewTemplates.parse("visits", """
                <c:set var="title">Visits of ${owner.lastName}</c:set>
                <c:forEach begin="1" end="${owner.visits.size()}" var="i">
                  <p>${i}: ${title}</p>
                </c:forEach>
                """, fragment -> { }, ViewTemplates.Dialect.JSP);
        // The loop counts: i and the body-set title are no model paths of their own.
        assertThat(reads).extracting(ViewTemplates.Read::path).containsOnly("owner.lastName", "owner.visits", "i",
                "title");
    }

    @Test
    void aFragmentReadsWhatItsArgumentsName(@TempDir Path resources) throws IOException {
        Path templates = Files.createDirectories(resources.resolve("templates/fragments")).getParent();
        Files.createDirectories(templates.resolve("owners"));
        Files.writeString(templates.resolve("fragments/inputField.html"), """
                <th:block th:fragment="input (label, name, type)">
                  <div th:with="valid=${!#fields.hasErrors(name)}">
                    <label th:for="${name}" th:text="${label}">Label</label>
                    <input th:case="'text'" type="text" th:field="*{__${name}__}" />
                    <span th:errors="*{__${name}__}">Error</span>
                  </div>
                </th:block>
                """);
        Files.writeString(templates.resolve("fragments/selectField.html"), """
                <th:block th:fragment="select (label, name, items)">
                  <select th:field="*{__${name}__}">
                    <option th:each="item : ${items}" th:value="${item}" th:text="${item}">dog</option>
                  </select>
                </th:block>
                """);
        Files.writeString(templates.resolve("owners/form.html"), """
                <form th:object="${owner}">
                  <input th:replace="~{fragments/inputField :: input (#{firstName}, 'firstName', 'text')}" />
                  <div sec:authorize="hasRole('ADMIN')">
                    <input th:replace="~{fragments/inputField :: input ('Phone', 'telephone', 'text')}" />
                  </div>
                  <input th:replace="~{fragments/selectField :: select ('Type', 'type', ${types})}" />
                </form>
                """);
        List<ViewTemplates.Read> reads = new ViewTemplates(List.of(resources), "templates/", ".html",
                ViewTemplates.Dialect.THYMELEAF).reads("owners/form").orElseThrow();
        assertThat(reads).extracting(ViewTemplates.Read::path)
                .filteredOn(path -> path.startsWith("owner") || path.startsWith("types"))
                .containsOnly("owner.firstName", "owner.telephone", "owner.type", "types", "types[]");
        // The caller's sec:authorize guards what the fragment reads, located in the caller.
        assertThat(reads).filteredOn(read -> read.path().equals("owner.telephone")).allSatisfy(read -> {
            assertThat(read.guards()).containsExactly("hasRole('ADMIN')");
            assertThat(read.guardTemplate()).isEqualTo("owners/form");
            assertThat(read.guardLine()).isEqualTo(3);
        });
        assertThat(reads).filteredOn(read -> read.path().equals("owner.firstName"))
                .allSatisfy(read -> assertThat(read.guards()).isEmpty());
    }
}
