package fixtures.grpcdynamic;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.ServerInterceptor;
import io.grpc.stub.StreamObserver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.grpc.server.service.GrpcService;

/**
 * The open methods come from configuration: AuthTracer can't tell which calls the first rule matches.
 */
@Configuration
class DynamicGrpcSecurityConfig {

    @Bean
    @GlobalServerInterceptor
    ServerInterceptor securityInterceptor(GrpcSecurity security, @Value("${grpc.open}") String open)
            throws Exception {
        return security
                .authorizeRequests(requests -> requests.methods(open).permitAll()
                        .allRequests().hasAuthority("ROLE_USER"))
                .build();
    }
}

@GrpcService
class DynamicGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello").build());
        responseObserver.onCompleted();
    }
}
