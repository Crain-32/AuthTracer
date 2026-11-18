package fixtures.kotlindsl

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component
import org.springframework.web.servlet.function.ServerRequest
import org.springframework.web.servlet.function.ServerResponse
import org.springframework.web.servlet.function.router

data class Report(val id: String)

@Component
class ReportHandler {

    fun find(request: ServerRequest): ServerResponse = ServerResponse.ok().body(Report(request.pathVariable("id")))
}

/** The Kotlin router DSL for Spring MVC functional endpoints. */
@Configuration
class KotlinDslRoutes {

    @Bean
    fun reportRoutes(handler: ReportHandler) = router {
        "/reports".nest {
            GET("/{id}", handler::find)
        }
    }
}
