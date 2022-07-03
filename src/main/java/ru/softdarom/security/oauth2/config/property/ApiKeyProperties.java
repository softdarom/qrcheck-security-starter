package ru.softdarom.security.oauth2.config.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

@Validated
@Getter
@Setter
@ConfigurationProperties(value = "spring.security.qrcheck.api-key")
public class ApiKeyProperties {

    /**
     * <p> Включение default api-key аутентификации на сервисе.
     * <p> Значение по-умолчанию false
     * <p> Доступные значения: true и false.
     **/
    private Boolean enabled = Boolean.FALSE;

    /**
     * <p> Имя header для аутентификации через api-key.
     * <p> Значение по-умолчанию "X-ApiKey-Authorization".
     **/
    private String headerName = "X-ApiKey-Authorization";

    @NotNull
    private Token token = new Token();

    @Valid
    @Getter
    @Setter
    public static class Token {

        /**
         * <p> Значение стандартного исходящего api-key для external auth service.
         * <p> Нужно указывать только при включении {@link ApiKeyProperties#enabled}.
         **/
        private String outgoing = "";

        /**
         * <p> Имя сервиса для получения доступных токенов
         * <p> Значение по-умолчанию spring.application.name
         * <p> Нужно указывать только при включении {@link ApiKeyProperties#enabled}.
         **/
        private String serviceName;
    }
}