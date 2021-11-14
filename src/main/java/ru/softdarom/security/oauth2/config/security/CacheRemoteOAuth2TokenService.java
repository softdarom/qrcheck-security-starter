package ru.softdarom.security.oauth2.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
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
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
        LOGGER.info("Пользователь пытается аутентифицироваться через токен доступа: {}", accessToken);
        var oAuthTokenInfo = verifyAccessToken(accessToken);
        if (!oAuthTokenInfo.getValid().isValid()) {
            LOGGER.warn(
                    "Не получилось аутентифицироваться через токен '{}' по причине '{}'. Вернуть ошибку аутентификации.",
                    accessToken, oAuthTokenInfo.getValid()
            );
            return new FailureOAuthClientAuthentication();
        }
        var tokenInfo = DEFAULT_ACCESS_TOKEN_CONVERTER.extractAuthentication(createMapAuth(oAuthTokenInfo));
        var oAuth2 = new UsernamePasswordAuthenticationToken(oAuthTokenInfo.getUserId(), accessToken, tokenInfo.getAuthorities());
        var authentication = new OAuth2Authentication(tokenInfo.getOAuth2Request(), oAuth2);
        authentication.setAuthenticated(true);
        return authentication;
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("The method is not supported!");
    }

    protected Map<String, ?> createMapAuth(OAuth2TokenDto dto) {
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
            LOGGER.info("Токен доступа будет проверен через внешний сервис");
            return Optional.ofNullable(
                    authHandlerExternalService.verify(properties.getToken().getOutgoing(), accessToken).getBody()
            ).orElseThrow();
        } catch (WebClientResponseException e) {
            LOGGER.error("Внешний сервис вернул ошибку! Вернуть ошибку авторизации", e);
            return new OAuth2TokenDto(TokenValidType.UNKNOWN);
        } catch (RuntimeException e) {
            LOGGER.error("Неизвестная ошибка после вызова внешнего сервиса! Вернуть ошибку авторизации", e);
            return new OAuth2TokenDto(TokenValidType.UNKNOWN);
        }
    }

    protected static class FailureOAuthClientAuthentication extends OAuth2Authentication {

        public FailureOAuthClientAuthentication() {
            super(DEFAULT_ACCESS_TOKEN_CONVERTER.extractAuthentication(Map.of()).getOAuth2Request(), null);
        }

        @Override
        public boolean isAuthenticated() {
            return false;
        }

        @Override
        public Object getCredentials() {
            return "";
        }

        @Override
        public Object getPrincipal() {
            return "UNKNOWN";
        }

    }
}