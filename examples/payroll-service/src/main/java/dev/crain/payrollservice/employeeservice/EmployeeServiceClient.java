package dev.crain.payrollservice.employeeservice;

import dev.crain.employees.v1.EmployeeDirectoryGrpc;
import dev.crain.employees.v1.EmployeeRecord;
import dev.crain.employees.v1.GetEmployeeRequest;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.client.GrpcChannelFactory;
import org.springframework.grpc.client.interceptor.security.BearerTokenAuthenticationInterceptor;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.publisher.MonoSink;

/**
 * employee-service's gRPC directory (src/main/proto/employee_directory.proto), on the channel
 * {@code spring.grpc.client.channel.employee-service.target} names.
 */
@Component
public class EmployeeServiceClient {

    /**
     * payroll-service's own OAuth2 client registration (client credentials), in application.yaml.
     */
    private static final String REGISTRATION = "payroll-service";

    private final EmployeeDirectoryGrpc.EmployeeDirectoryStub directory;
    private final ReactiveOAuth2AuthorizedClientManager authorizedClients;

    public EmployeeServiceClient(GrpcChannelFactory channels, ReactiveOAuth2AuthorizedClientManager authorizedClients) {
        this.directory = EmployeeDirectoryGrpc.newStub(channels.createChannel("employee-service"));
        this.authorizedClients = authorizedClients;
    }

    /**
     * Relays the caller's bearer token, so employee-service authorizes the same user payroll-service did. A reactive
     * request keeps its caller in the Reactor context, not on the thread, so the token is read from there.
     */
    public Mono<EmployeeDto> employee(long id) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> ((AbstractOAuth2TokenAuthenticationToken<?>) context.getAuthentication()).getToken()
                        .getTokenValue())
                .flatMap(token -> Mono.<EmployeeRecord>create(sink -> directory
                        .withInterceptors(new BearerTokenAuthenticationInterceptor(token))
                        .getEmployee(GetEmployeeRequest.newBuilder().setId(id).build(), new SinkObserver<>(sink))))
                .map(EmployeeDto::from);
    }

    /**
     * As payroll-service itself, for work no user asked for: with its own token, which identity-service issues to its
     * client registration by client credentials (the manager keeps it until it expires). employee-service authorizes
     * the service: its token has the read scope and no roles, so the salary, which only ADMIN and AUDITOR may see, is
     * left out.
     */
    public Mono<EmployeeDto> employeeAsPayroll(long id) {
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest.withClientRegistrationId(REGISTRATION)
                .principal(REGISTRATION)
                .build();
        return authorizedClients.authorize(request)
                .map(client -> client.getAccessToken().getTokenValue())
                .flatMap(token -> Mono.<EmployeeRecord>create(sink -> directory
                        .withInterceptors(new BearerTokenAuthenticationInterceptor(token))
                        .getEmployee(GetEmployeeRequest.newBuilder().setId(id).build(), new SinkObserver<>(sink))))
                .map(EmployeeDto::from);
    }

    /**
     * A unary call's one reply, or its error, into a {@link Mono}.
     */
    private record SinkObserver<T>(MonoSink<T> sink) implements StreamObserver<T> {

        @Override
        public void onNext(T value) {
            sink.success(value);
        }

        @Override
        public void onError(Throwable error) {
            sink.error(error);
        }

        @Override
        public void onCompleted() {
            sink.success();
        }
    }
}
