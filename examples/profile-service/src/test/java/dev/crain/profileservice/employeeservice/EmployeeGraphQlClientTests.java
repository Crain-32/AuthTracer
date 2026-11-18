package dev.crain.profileservice.employeeservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.client.MockRestServiceServer;

@RestClientTest(components = EmployeeGraphQlClient.class, properties = "employee-service.base-url=http://employee-service")
class EmployeeGraphQlClientTests {

    @Autowired
    EmployeeGraphQlClient client;

    @Autowired
    MockRestServiceServer server;

    @BeforeEach
    void signIn() {
        Jwt jwt = Jwt.withTokenValue("caller-token").header("alg", "none").subject("alice")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void readsAnEmployeeWithTheCallersToken() {
        server.expect(requestTo("http://employee-service/graphql")).andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer caller-token"))
                .andExpect(content().string(containsString("employee(id: $id)")))
                .andRespond(withSuccess("""
                        {"data": {"employee": {"id": "1", "firstName": "Alice", "lastName": "Anders",
                         "email": "alice@example.com", "ssn": "***-**-****", "salary": null}}}
                        """, MediaType.APPLICATION_JSON));

        EmployeeDto employee = client.employee(1);

        assertThat(employee.id()).isEqualTo(1);
        assertThat(employee.ssn()).isEqualTo("***-**-****");
        assertThat(employee.salary()).isNull();
        server.verify();
    }

    @Test
    void listsEmployees() {
        server.expect(requestTo("http://employee-service/graphql"))
                .andExpect(header("Authorization", "Bearer caller-token"))
                .andRespond(withSuccess("""
                        {"data": {"employees": [
                          {"id": "1", "firstName": "Alice", "lastName": "Anders", "email": "alice@example.com",
                           "ssn": "***-**-****", "salary": 85000.0},
                          {"id": "4", "firstName": "Dan", "lastName": "Diaz", "email": "dan@example.com",
                           "ssn": "***-**-****", "salary": 70000.0}]}}
                        """, MediaType.APPLICATION_JSON));

        List<EmployeeDto> employees = client.employees();

        assertThat(employees).extracting(EmployeeDto::id).containsExactly(1L, 4L);
        assertThat(employees.getFirst().salary()).isEqualByComparingTo(new BigDecimal("85000"));
        server.verify();
    }
}
