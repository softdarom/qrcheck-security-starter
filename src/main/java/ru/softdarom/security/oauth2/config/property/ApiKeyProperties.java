package ru.softdarom.security.oauth2.config.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.Set;

@Validated
@Getter
@Setter
@ConfigurationProperties(value = "spring.security.qrcheck.api-key")
public class ApiKeyProperties {

    /**
     * <p> Включение api-key аутентификации на сервисе.
     * <p> Значение по-умолчанию false
     * <p> Доступные значения: true и false.
     **/
    private Boolean hasApiKeyAuth = Boolean.FALSE;

    /**
     * <p> Имя header для аутентификации через api-key.
     * <p> Значение по-умолчанию "X-ApiKey-Authorization".
     **/
    private String headerName = "X-ApiKey-Authorization";

    @NotNull
    private Token token;

    @Valid
    @Getter
    @Setter
    public static class Token {

        /**
         *  Значение исходящего api-key.
         *  Не должно быть пустым!
         **/
        @NotEmpty
        private String outgoing;

        /**
         * <p> Варианты входящих api-key представленные как множество.
         * <p> Нужно указывать только при включении {@link ApiKeyProperties#hasApiKeyAuth}.
         **/
        private Set<String> incoming = Set.of();

    }
}