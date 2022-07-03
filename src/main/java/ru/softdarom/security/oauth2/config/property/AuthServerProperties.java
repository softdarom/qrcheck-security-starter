package ru.softdarom.security.oauth2.config.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(value = "spring.security.qrcheck.auth-server")
public class AuthServerProperties {

    /**
     * <p> Хост для подключения к authorization server.
     * <p> Значение по-умолчанию <a href="http://auth-handler:8000">http://auth-handler:8000</a>.
     **/
    private String host = "http://auth-handler:8000";

    /**
     * <p> Путь до конечной точки для получения incoming токенов.
     * <p> Значение по-умолчанию "/apikeys".
     **/
    private String incomingApiKeysPath = "/apiKeys/incoming";

    /**
     * <p> Путь до конечной точки для получения incoming токенов.
     * <p> Значение по-умолчанию "/apikeys".
     **/
    private String outgoingApiKeysPath = "/apiKeys/outgoing";

    /**
     * <p> Путь до конечной точки для верификации access token в authorization server.
     * <p> Значение по-умолчанию "/tokens/verify".
     **/
    private String verifyPath = "/tokens/verify";

    /**
     * <p> Значение для request param для получения incoming токенов в authorization server.
     * <p> Значение по-умолчанию "serviceName".
     **/
    private String serviceNameQueryParamName = "serviceName";

    /**
     * <p> Значение для request param для верификации access token в authorization server.
     * <p> Значение по-умолчанию "accessToken".
     **/
    private String accessTokenQueryParamName = "accessToken";

}
