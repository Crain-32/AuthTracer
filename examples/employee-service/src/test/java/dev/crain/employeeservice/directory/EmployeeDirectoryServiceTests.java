package dev.crain.employeeservice.directory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;

import java.time.Instant;
import java.util.List;

import dev.crain.employees.v1.EmployeeDirectoryGrpc;
import dev.crain.employees.v1.EmployeeDirectoryGrpc.EmployeeDirectoryBlockingStub;
import dev.crain.employees.v1.EmployeeRecord;
import dev.crain.employees.v1.GetEmployeeRequest;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.grpc.test.autoconfigure.AutoConfigureTestGrpcTransport;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.grpc.client.interceptor.security.BearerTokenAuthenticationInterceptor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The gRPC directory in process, with tokens decoded by a stub: the same converter and checks as the REST API.
 */
@SpringBootTest(properties = { "management.tracing.export.enabled=false", "management.health.rabbit.enabled=false",
        "spring.rabbitmq.listener.simple.auto-startup=false" })
@AutoConfigureTestGrpcTransport
class EmployeeDirectoryServiceTests {

    @Autowired
    GrpcChannelFactory channels;

    @MockitoBean
    JwtDecoder jwtDecoder;

    @BeforeEach
    void tokens() {
        given(jwtDecoder.decode("admin-token")).willReturn(jwt("admin", List.of("employees.read"), List.of("ADMIN", "USER")));
        given(jwtDecoder.decode("alice-token")).willReturn(jwt("alice", List.of("employees.read"), List.of("USER")));
        given(jwtDecoder.decode("openid-token")).willReturn(jwt("alice", List.of("openid"), List.of("USER")));
        // payroll-service's own token (client credentials): the read scope, and no roles claim.
        given(jwtDecoder.decode("payroll-service-token")).willReturn(Jwt.withTokenValue("payroll-service-token")
                .header("alg", "RS256").subject("payroll-service").claim("scope", "employees.read")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build());
    }

    @Test
    void adminsGetTheSalary() {
        EmployeeRecord alice = directory("admin-token").getEmployee(request(1));

        assertThat(alice.getFirstName()).isEqualTo("Alice");
        assertThat(alice.getManagerUsername()).isEqualTo("bob");
        assertThat(alice.hasSalary()).isTrue();
        assertThat(alice.getSalary()).isEqualTo("85000");
    }

    @Test
    void usersGetNoSalary() {
        EmployeeRecord alice = directory("alice-token").getEmployee(request(1));

        assertThat(alice.getEmail()).isEqualTo("alice@example.com");
        assertThat(alice.hasSalary()).isFalse();
    }

    @Test
    void aServiceGetsTheEmployeeButNotTheSalary() {
        EmployeeRecord alice = directory("payroll-service-token").getEmployee(request(1));

        assertThat(alice.getFirstName()).isEqualTo("Alice");
        assertThat(alice.getLastName()).isEqualTo("Anders");
        assertThat(alice.hasSalary()).isFalse();
    }

    @Test
    void callsNeedTheReadScope() {
        assertThatExceptionOfType(StatusRuntimeException.class)
                .isThrownBy(() -> directory("openid-token").getEmployee(request(1)))
                .satisfies(ex -> assertThat(ex.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED));
    }

    @Test
    void callsNeedAToken() {
        EmployeeDirectoryBlockingStub anonymous = EmployeeDirectoryGrpc.newBlockingStub(channels.createChannel("test"));

        assertThatExceptionOfType(StatusRuntimeException.class)
                .isThrownBy(() -> anonymous.getEmployee(request(1)))
                .satisfies(ex -> assertThat(ex.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED));
    }

    @Test
    void unknownEmployeesAreNotFound() {
        assertThatExceptionOfType(StatusRuntimeException.class)
                .isThrownBy(() -> directory("admin-token").getEmployee(request(99)))
                .satisfies(ex -> assertThat(ex.getStatus().getCode()).isEqualTo(Status.Code.NOT_FOUND));
    }

    private EmployeeDirectoryBlockingStub directory(String token) {
        return EmployeeDirectoryGrpc.newBlockingStub(channels.createChannel("test"))
                .withInterceptors(new BearerTokenAuthenticationInterceptor(token));
    }

    private static GetEmployeeRequest request(long id) {
        return GetEmployeeRequest.newBuilder().setId(id).build();
    }

    private static Jwt jwt(String subject, List<String> scopes, List<String> roles) {
        return Jwt.withTokenValue(subject + "-token").header("alg", "RS256").subject(subject)
                .claim("scope", String.join(" ", scopes)).claim("roles", roles)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }
}
