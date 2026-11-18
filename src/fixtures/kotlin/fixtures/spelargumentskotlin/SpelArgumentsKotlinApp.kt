package fixtures.spelargumentskotlin

import org.springframework.context.annotation.Configuration
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

/**
 * EXPR-02 in Kotlin, compiled without Java parameter names: with kotlin-reflect present, Spring takes Kotlin's own;
 * a check on the caller's Authentication, an enum and a primitive.
 */
@Configuration
@EnableMethodSecurity
class SpelArgumentsKotlinConfig

enum class Region { EU, US }

@Service
class Reports {

    @PreAuthorize("#owner == #authentication.name")
    fun owned(owner: String, authentication: Authentication): String = owner

    @PreAuthorize("#region.name() == 'EU' and #year > 2000")
    fun yearly(region: Region, year: Int): String = "$region $year"
}

@RestController
class ReportsController(private val reports: Reports) {

    @GetMapping("/reports/{owner}")
    fun owned(@PathVariable owner: String, authentication: Authentication): String =
        reports.owned(owner, authentication)

    @GetMapping("/reports")
    fun yearly(region: Region, year: Int): String = reports.yearly(region, year)
}
