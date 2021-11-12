package ru.softdarom.security.oauth2.config.security;

import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

import static lombok.AccessLevel.PRIVATE;

@NoArgsConstructor(access = PRIVATE)
public class ApiKeyAuthorizationConfig {

    public static class ApiKeyAuthorizationFilter extends AbstractPreAuthenticatedProcessingFilter {

        private static final String NOT_AVAILABILITY = "N/A";

        private final String apiKeyHeaderName;

        public ApiKeyAuthorizationFilter(String apiKeyHeaderName) {
            this.apiKeyHeaderName = apiKeyHeaderName;
        }

        @Override
        protected String getPreAuthenticatedPrincipal(HttpServletRequest request) {
            return NOT_AVAILABILITY;
        }

        @Override
        protected String getPreAuthenticatedCredentials(HttpServletRequest request) {
            return Optional.ofNullable(request.getHeader(apiKeyHeaderName)).orElse(NOT_AVAILABILITY);
        }
    }

    public static class ApiKeyAuthentication implements Authentication {

        private final Collection<? extends GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_API_KEY"));
        private final String apiKey;
        private boolean authenticated;

        public ApiKeyAuthentication(String apiKey) {
            this(apiKey, true);
        }

        public ApiKeyAuthentication(String apiKey, boolean authenticated) {
            this.apiKey = apiKey;
            this.authenticated = authenticated;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public String getCredentials() {
            return apiKey;
        }

        @Override
        public String getDetails() {
            return getCredentials();
        }

        @Override
        public String getPrincipal() {
            return getCredentials();
        }

        @Override
        public boolean isAuthenticated() {
            return authenticated;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            this.authenticated = isAuthenticated;
        }

        @Override
        public String getName() {
            return getCredentials();
        }
    }
}