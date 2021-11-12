package ru.softdarom.security.oauth2.config.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Max;
import javax.validation.constraints.NotNull;

@Validated
@Getter
@Setter
@ConfigurationProperties("spring.security.qrcheck.oauth2")
public class OAuth2Properties {

    private Boolean enabled;

    @NotNull
    private AuthServer authServer = new AuthServer();

    @Getter
    @Setter
    public static class AuthServer {

        private String host = "http://auth-handler:8000";

        private String path = "/tokens/verify";

        private String queryParamName = "accessToken";

        @NotNull
        private Cache cache = new Cache();

        @Validated
        @Getter
        @Setter
        public static class Cache {

            @Max(3600) // should not be more hour
            private Long expireAfterWriteInSec = 900L;

            @Max(5_000_000) // one string is 9 byte, 5kk * 9 = 45kk, it is 45mb of the heap
            private Long size = 1_000_000L;

        }

    }
}