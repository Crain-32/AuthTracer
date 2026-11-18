package dev.crain.payrollservice.employeeservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import dev.crain.employees.v1.EmployeeDirectoryGrpc;
import dev.crain.employees.v1.EmployeeRecord;
import dev.crain.employees.v1.GetEmployeeRequest;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.grpc.client.ChannelBuilderOptions;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

/**
 * Calls an in-process directory that records the Authorization header each call carries.
 */
class EmployeeServiceClientTests {

    private static final Metadata.Key<String> AUTHORIZATION = Metadata.Key.of("Authorization",
            Metadata.ASCII_STRING_MARSHALLER);

    private final AtomicReference<String> authorization = new AtomicReference<>();
    private Server server;
    private ManagedChannel channel;

    @BeforeEach
    void startDirectory() throws IOException {
        String name = InProcessServerBuilder.generateName();
        ServerInterceptor recordAuthorization = new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata headers,
                    ServerCallHandler<Q, R> next) {
                authorization.set(headers.get(AUTHORIZATION));
                return next.startCall(call, headers);
            }
        };
        server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(ServerInterceptors.intercept(new Directory(), recordAuthorization)).build().start();
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
    }

    @AfterEach
    void stopDirectory() {
        channel.shutdownNow();
        server.shutdownNow();
    }

    @Test
    void relaysTheCallersBearerToken() {
        Jwt jwt = Jwt.withTokenValue("caller-token").header("alg", "none").subject("alice")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();

        EmployeeDto lead = new EmployeeServiceClient(new OneChannel(channel), NO_CLIENTS).employee(2)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
                .block();

        assertThat(lead.firstName()).isEqualTo("Bob");
        assertThat(lead.salary()).isEqualTo(new BigDecimal("120000"));
        assertThat(authorization.get()).isEqualTo("Bearer caller-token");
    }

    @Test
    void anUnsentSalaryIsNull() {
        Jwt jwt = Jwt.withTokenValue("caller-token").header("alg", "none").subject("alice")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();

        EmployeeDto alice = new EmployeeServiceClient(new OneChannel(channel), NO_CLIENTS).employee(1)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt)))
                .block();

        assertThat(alice.salary()).isNull();
    }

    @Test
    void readsAsPayrollServiceWithItsOwnToken() {
        ClientRegistration registration = ClientRegistration.withRegistrationId("payroll-service")
                .clientId("payroll-service").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri("http://localhost:9000/oauth2/token").build();
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "service-token",
                Instant.now(), Instant.now().plusSeconds(60));
        AtomicReference<OAuth2AuthorizeRequest> asked = new AtomicReference<>();
        ReactiveOAuth2AuthorizedClientManager clients = request -> {
            asked.set(request);
            return Mono.just(new OAuth2AuthorizedClient(registration, request.getPrincipal().getName(), token));
        };

        // No caller in the context: a listener's call.
        EmployeeDto lead = new EmployeeServiceClient(new OneChannel(channel), clients).employeeAsPayroll(2).block();

        assertThat(lead.firstName()).isEqualTo("Bob");
        assertThat(authorization.get()).isEqualTo("Bearer service-token");
        assertThat(asked.get().getClientRegistrationId()).isEqualTo("payroll-service");
    }

    /**
     * Bob with his salary; anyone else without one, as for a caller who may not see it.
     */
    private static final class Directory extends EmployeeDirectoryGrpc.EmployeeDirectoryImplBase {

        @Override
        public void getEmployee(GetEmployeeRequest request, StreamObserver<EmployeeRecord> responseObserver) {
            EmployeeRecord.Builder record = EmployeeRecord.newBuilder().setId(request.getId());
            if (request.getId() == 2) {
                record.setFirstName("Bob").setLastName("Brown").setSalary("120000");
            }
            responseObserver.onNext(record.build());
            responseObserver.onCompleted();
        }
    }

    private static final ReactiveOAuth2AuthorizedClientManager NO_CLIENTS = request -> Mono.empty();

    private record OneChannel(ManagedChannel channel) implements GrpcChannelFactory {

        @Override
        public boolean supports(String target) {
            return true;
        }

        @Override
        public ManagedChannel createChannel(String target, ChannelBuilderOptions options) {
            return channel;
        }
    }
}
