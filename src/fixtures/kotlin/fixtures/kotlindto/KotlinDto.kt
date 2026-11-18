package fixtures.kotlindto

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Kotlin puts an annotation written on a constructor property on the constructor parameter, where
 * jackson-module-kotlin reads it.
 */
data class Member(@JsonProperty("display_name") val name: String, val email: String)

@RestController
class MemberController {

    @GetMapping("/member")
    fun member(): Member = Member("Ada", "ada@example.com")
}
