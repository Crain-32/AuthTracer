package fixtures.jwkset;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Decision 0049: a resource server given its JWK set directly, which Boot reads instead of the issuer's OpenID
 * configuration; and an OAuth2 client registration for calls of its own.
 */
@SpringBootApplication
class JwkSetApp {
}
