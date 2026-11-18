package fixtures.kotlinproperties

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Constructor properties, whose annotations Kotlin puts on the constructor's parameters, next to a property the
 * body declares and one computed without a field.
 */
data class Member(@JsonProperty("display_name") val name: String, val email: String) {

    @JsonIgnore
    val token: String = "t"

    val initials: String
        get() = name.take(1)

    companion object {
        const val KIND = "member"
    }
}

@RestController
class MemberController {

    @GetMapping("/member")
    fun member(): Member = Member("Ada", "ada@example.com")
}
