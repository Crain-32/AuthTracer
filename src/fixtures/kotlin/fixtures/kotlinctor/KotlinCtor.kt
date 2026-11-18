package fixtures.kotlinctor

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * A primary constructor whose parameters aren't all properties: the annotations of those that are stay with their
 * properties, and a plain parameter's go to the body's property of the same name, as jackson-module-kotlin links
 * them by name.
 */
class Account(
    @JsonProperty("account_holder") val holder: String,
    visible: Int,
    @JsonIgnore val pin: String,
    @JsonProperty("short_code") code: String,
) {

    val masked: String = pin.take(visible)

    val code: String = code.uppercase()
}

@RestController
class AccountController {

    @GetMapping("/account")
    fun account(): Account = Account("Ada", 2, "1234", "ab")
}
