package fixtures.grpc;

import io.grpc.stub.StreamObserver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;

/**
 * A gRPC service (stubs generated from src/fixtures/proto/greeter.proto) with Spring gRPC's request rules.
 */
@Configuration
@EnableMethodSecurity
class GrpcSecurityConfig {

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurity(GrpcSecurity grpc) throws Exception {
        return grpc
                .authorizeRequests(requests -> requests
                        .methods("fixtures.grpc.Greeter/SayHello").hasAuthority("SCOPE_greet")
                        .methods("fixtures.grpc.Greeter/list_*").hasAnyAuthority("SCOPE_greet", "SCOPE_list")
                        .methods("grpc.*/*").permitAll()
                        .allRequests().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }
}

@GrpcService
class GreeterService extends GreeterGrpc.GreeterImplBase {

    private final Notes notes;

    GreeterService(Notes notes) {
        this.notes = notes;
    }

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello " + request.getName())
                .setSecretNote(notes.secret()).addHistory(Greeting.newBuilder().setText(request.getName()).build())
                .build());
        responseObserver.onCompleted();
    }

    @Override
    @PreAuthorize("hasRole('LISTER')")
    public void listGreetings(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hi").build());
        responseObserver.onCompleted();
    }

    @Override
    public void ping(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("pong").build());
        responseObserver.onCompleted();
    }
}

@Service
class Notes {

    @PreAuthorize("hasRole('ADMIN')")
    String secret() {
        return "s";
    }
}
