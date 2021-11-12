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

    private Boolean hasApiKeyAuth;

    private String headerName = "X-ApiKey-Authorization";

    @NotNull
    private Token token;

    @Valid
    @Getter
    @Setter
    public static class Token {

        @NotEmpty
        private String outgoing;

        private Set<String> incoming = Set.of();

    }
}