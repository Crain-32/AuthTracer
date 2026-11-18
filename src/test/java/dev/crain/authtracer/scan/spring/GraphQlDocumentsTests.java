package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class GraphQlDocumentsTests {

    @Test
    void textThatIsntADocumentHasNoOperation() {
        // documentName's argument passed to document(..), and a fragment cut short.
        assertThat(GraphQlDocuments.firstOperation("bookDetails")).isEmpty();
        assertThat(GraphQlDocuments.firstOperation("fragment F on Book")).isEmpty();
    }

    @Test
    void anAnonymousQuery() {
        GraphQlDocuments.Operation operation = GraphQlDocuments.firstOperation("{ person(id: 1) { name } }")
                .orElseThrow();
        assertThat(operation.type()).isEqualTo("QUERY");
        assertThat(operation.fields()).containsExactly("person");
    }

    @Test
    void argumentsStringsAndDirectivesDontCountAsFields() {
        GraphQlDocuments.Operation operation = GraphQlDocuments.firstOperation("""
                query search($filter: Filter = {name: "a { b }", tags: ["x"]}) @cached(ttl: 5) {
                  people(filter: $filter, first: -1.5e3) @include(if: true) { name }
                  # count: total
                  total: count(where: {active: true})
                  __typename
                }
                """).orElseThrow();
        assertThat(operation.fields()).containsExactly("people", "count", "__typename");
        assertThat(operation.field("total")).contains("count");
        assertThat(operation.field("people[0].name")).contains("people");
        assertThat(operation.field("missing")).contains("people");
    }

    @Test
    void fragmentsAreSkipped() {
        GraphQlDocuments.Operation operation = GraphQlDocuments.firstOperation("""
                fragment parts on Person { name salary }
                mutation {
                  ...topLevel
                  ... on Mutation { ignored }
                  rename(id: 1) { ...parts }
                }
                """).orElseThrow();
        assertThat(operation.type()).isEqualTo("MUTATION");
        assertThat(operation.fields()).containsExactly("rename");
    }

    @Test
    void onlyFragmentsIsNoOperation() {
        assertThat(GraphQlDocuments.firstOperation("fragment F on Book { title } fragment G on Author { name }"))
                .isEmpty();
    }

    @Test
    void anInlineFragmentUnderADirectiveEscapedQuotesAndATrailingComment() {
        GraphQlDocuments.Operation operation = GraphQlDocuments.firstOperation("""
                query($details: Boolean!) {
                  ... @include(if: $details) { details }
                  search(text: "say \\"hi\\"") { id }
                }
                # last line, no newline after it""".stripTrailing()).orElseThrow();
        assertThat(operation.fields()).containsExactly("search");
        // Without a response path, the first root field.
        assertThat(operation.field(null)).contains("search");
        assertThat(operation.field("")).contains("search");
    }

    @Test
    void aSubscription() {
        assertThat(GraphQlDocuments.firstOperation("subscription { updates { id } }").orElseThrow().type())
                .isEqualTo("SUBSCRIPTION");
    }
}
