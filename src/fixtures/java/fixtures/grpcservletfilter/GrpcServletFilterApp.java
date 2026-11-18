package fixtures.grpcservletfilter;

import java.io.IOException;

import fixtures.grpc.GreeterGrpc;
import fixtures.grpc.HelloReply;
import fixtures.grpc.HelloRequest;
import io.grpc.stub.StreamObserver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0070 (amended): gRPC served through the servlet container arrives as a POST through the servlet filters,
 * Boot's health service's calls too.
 */
@SpringBootApplication
@EnableWebSecurity
class GrpcServletFilterApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/grpc.health.v1.Health/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@Component
class AuditFilter extends OncePerRequestFilter {

    private final RestClient client = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        client.post().uri("/audit").retrieve().toBodilessEntity();
        chain.doFilter(request, response);
    }
}

@GrpcService
class PartialGreeter extends GreeterGrpc.GreeterImplBase {

    @Override
    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
        responseObserver.onNext(HelloReply.newBuilder().setMessage("Hello").build());
        responseObserver.onCompleted();
    }
}
