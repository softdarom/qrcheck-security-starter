package ru.softdarom.security.oauth2.config.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authentication;
    }

    @Override
    public final boolean supports(Class<?> authentication) {
        return isPreAuthenticatedAuthenticationToken(authentication) || isFailureOAuthClientAuthentication(authentication);
    }

    private boolean isPreAuthenticatedAuthenticationToken(Class<?> authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private boolean isFailureOAuthClientAuthentication(Class<?> authentication) {
        return CacheRemoteOAuth2TokenService.FailureOAuthClientAuthentication.class.isAssignableFrom(authentication);
    }
}