package fixtures.grpckotlin

import fixtures.grpc.GreeterGrpcKt
import fixtures.grpc.HelloReply
import fixtures.grpc.HelloRequest
import org.springframework.context.annotation.Configuration
import org.springframework.grpc.client.ImportGrpcClients
import org.springframework.grpc.server.service.GrpcService
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/** grpc-kotlin: a coroutine service, and a coroutine stub bean calling it. */
@Configuration
@EnableMethodSecurity
@ImportGrpcClients(target = "greeter", types = [GreeterGrpcKt.GreeterCoroutineStub::class])
class KotlinGrpcConfig

@GrpcService
class KotlinGreeter(private val notes: KotlinNotes) : GreeterGrpcKt.GreeterCoroutineImplBase() {

    override suspend fun sayHello(request: HelloRequest): HelloReply =
        HelloReply.newBuilder().setMessage(request.name).setSecretNote(notes.secret()).build()

    @PreAuthorize("hasRole('PINGER')")
    override suspend fun ping(request: HelloRequest): HelloReply = HelloReply.newBuilder().setMessage("pong").build()
}

@Service
class KotlinNotes {

    @PreAuthorize("hasRole('ADMIN')")
    fun secret(): String = "s"
}

@RestController
class KotlinGreetingController(private val greeter: GreeterGrpcKt.GreeterCoroutineStub) {

    @GetMapping("/kotlin/greetings")
    suspend fun greet(): HelloReply = greeter.sayHello(HelloRequest.getDefaultInstance())
}
