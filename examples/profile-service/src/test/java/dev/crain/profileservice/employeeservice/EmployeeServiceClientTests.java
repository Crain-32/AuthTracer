package dev.crain.profileservice.employeeservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.client.MockRestServiceServer;

@RestClientTest(components = EmployeeServiceClient.class, properties = "employee-service.base-url=http://employee-service")
class EmployeeServiceClientTests {

    @Autowired
    EmployeeServiceClient client;

    @Autowired
    MockRestServiceServer server;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void relaysTheCallersBearerToken() {
        Jwt jwt = Jwt.withTokenValue("caller-token").header("alg", "none").subject("alice")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
        server.expect(requestTo("http://employee-service/employees/1"))
                .andExpect(header("Authorization", "Bearer caller-token"))
                .andRespond(withSuccess("""
                        {"id":1,"firstName":"Alice","lastName":"Anders","email":"alice@example.com",
                         "ssn":"***-**-****","salary":null,"managerUsername":"bob"}
                        """, MediaType.APPLICATION_JSON));

        EmployeeDto employee = client.getEmployee(1);

        assertThat(employee.email()).isEqualTo("alice@example.com");
        assertThat(employee.salary()).isNull();
        server.verify();
    }
}
