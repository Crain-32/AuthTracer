package fixtures.grpcreflection;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.BindableService;
import io.grpc.protobuf.services.ProtoReflectionService;
import io.grpc.protobuf.services.ProtoReflectionServiceV1;
import io.grpc.stub.StreamObserver;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.config.Customizer;

/**
 * Decision 0059: server reflection registered by hand, both grpc-java's v1alpha service and v1, while Boot's own is
 * turned off; the rules permit grpc.* to anyone.
 */
@SpringBootApplication
class GrpcReflectionApp {

    @Bean
    BindableService reflection() {
        return ProtoReflectionServiceV1.newInstance();
    }

    @Bean
    @SuppressWarnings("deprecation")
    BindableService legacyReflection() {
        return ProtoReflectionService.newInstance();
    }

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurity(GrpcSecurity grpc) throws Exception {
        return grpc.authorizeRequests(requests -> requests.methods("grpc.*/*").permitAll()
                        .allRequests().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }
}

@GrpcService
class GreeterService extends GreeterGrpc.GreeterImplBase {

    @Override
    public void ping(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("pong").build());
        responseObserver.onCompleted();
    }
}
