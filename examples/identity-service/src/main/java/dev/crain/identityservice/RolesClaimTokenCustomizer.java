package dev.crain.identityservice;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Adds a {@code roles} claim to JWT access tokens issued for a user principal. Roles are the
 * user's {@code ROLE_*} authorities with the prefix stripped, e.g. {@code ["USER","ADMIN"]}.
 * <p>
 * Tokens issued to the client itself ({@code client_credentials}) carry no {@code roles} claim.
 * The authorization server picks this bean up by its generic type
 * {@code OAuth2TokenCustomizer<JwtEncodingContext>}.
 */
@Component
class RolesClaimTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    static final String ROLES_CLAIM = "roles";

    private static final String ROLE_PREFIX = "ROLE_";

    private static final Logger log = LoggerFactory.getLogger(RolesClaimTokenCustomizer.class);

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }
        Authentication principal = context.getPrincipal();
        String clientId = context.getRegisteredClient().getClientId();
        String grantType = (context.getAuthorizationGrantType() != null)
                ? context.getAuthorizationGrantType().getValue() : "unknown";

        if (principal == null || principal instanceof OAuth2ClientAuthenticationToken) {
            log.info("Access token for client '{}' (grant {}) has no user principal; no roles claim added",
                    clientId, grantType);
            return;
        }

        // Only ROLE_* authorities: Spring Security 7 also adds FACTOR_* authorities on login.
        List<String> roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority != null && authority.startsWith(ROLE_PREFIX))
                .map(authority -> authority.substring(ROLE_PREFIX.length()))
                .sorted()
                .toList();
        context.getClaims().claim(ROLES_CLAIM, roles);

        log.info("Customized access token for user '{}' (client '{}', grant {}): roles={} scopes={}",
                principal.getName(), clientId, grantType, roles, context.getAuthorizedScopes());
    }

}
