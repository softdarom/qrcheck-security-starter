package ru.softdarom.security.oauth2.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import ru.softdarom.security.oauth2.config.property.ApiKeyProperties;
import ru.softdarom.security.oauth2.dto.OAuth2TokenDto;
import ru.softdarom.security.oauth2.dto.base.TokenValidType;
import ru.softdarom.security.oauth2.service.AuthHandlerExternalService;

import java.util.Map;
import java.util.Optional;

@Slf4j(topic = "SECURITY")
public class CacheRemoteOAuth2TokenService implements ResourceServerTokenServices {

    private static final AccessTokenConverter DEFAULT_ACCESS_TOKEN_CONVERTER = new DefaultAccessTokenConverter();

    private final ApiKeyProperties properties;
    private final AuthHandlerExternalService authHandlerExternalService;

    public CacheRemoteOAuth2TokenService(ApiKeyProperties properties, AuthHandlerExternalService authHandlerExternalService) {
        this.properties = properties;
        this.authHandlerExternalService = authHandlerExternalService;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws InvalidTokenException {
        LOGGER.debug("A user tries log in with an access token: '{}'", accessToken);
        var oAuthTokenInfo = verifyAccessToken(accessToken);
        checkToken(oAuthTokenInfo);
        LOGGER.debug("A user (id: {}) was authenticated", oAuthTokenInfo.getUserId());
        var tokenInfo = DEFAULT_ACCESS_TOKEN_CONVERTER.extractAuthentication(createMapAuth(oAuthTokenInfo));
        var oAuth2 = new UsernamePasswordAuthenticationToken(oAuthTokenInfo.getUserId(), accessToken, tokenInfo.getAuthorities());
        var authentication = new OAuth2Authentication(tokenInfo.getOAuth2Request(), oAuth2);
        authentication.setAuthenticated(true);
        return authentication;
    }

    private void checkToken(OAuth2TokenDto oAuthTokenInfo) {
        LOGGER.debug("Checking a token");
        if (!oAuthTokenInfo.getValid().isValid()) {
            throw new InvalidTokenException("Unauthorized. Token is " + oAuthTokenInfo.getValid().name().toLowerCase());
        }
        LOGGER.debug("Token is valid. Continue.");
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("The method is not supported!");
    }

    protected Map<String, Object> createMapAuth(OAuth2TokenDto dto) {
        return Map.of(
                "client_id", String.valueOf(dto.getUserId()),
                "azp", dto.getAzp(),
                "aud", dto.getAud(),
                "sub", dto.getSub(),
                "authorities", dto.getScopes()
        );
    }

    protected OAuth2TokenDto verifyAccessToken(String accessToken) {
        try {
            LOGGER.debug("An access token will be verified via an external service.");
            return Optional.ofNullable(
                    authHandlerExternalService.verify(properties.getToken().getOutgoing(), accessToken).getBody()
            ).orElseThrow();
        } catch (WebClientResponseException e) {
            LOGGER.error("Feign client has returned an error! Return authorization error.", e);
            return new OAuth2TokenDto(TokenValidType.UNKNOWN);
        } catch (RuntimeException e) {
            LOGGER.error("Unknown exception after a call of an external service! Return authorization error.", e);
            return new OAuth2TokenDto(TokenValidType.UNKNOWN);
        }
    }
}