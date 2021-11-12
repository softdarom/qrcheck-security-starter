package ru.softdarom.security.oauth2.config.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.time.Duration;

@Validated
@Getter
@Setter
@ConfigurationProperties("spring.security.qrcheck.oauth2")
public class OAuth2Properties {

    /**
     * <p> Включение oauth2 на сервисе.
     * <p> Значение по-умолчанию true.
     * <p> Доступные значения: true и false.
     **/
    private Boolean enabled;

    @NotNull
    private AuthServer authServer = new AuthServer();

    @Getter
    @Setter
    public static class AuthServer {

        /**
         * <p> Хост для подключения к authorization server.
         * <p> Значение по-умолчанию "http://auth-handler:8000".
         **/
        private String host = "http://auth-handler:8000";

        /**
         * <p> Путь до конечной точки для верификации access token в authorization server.
         * <p> Значение по-умолчанию "/tokens/verify".
         **/
        private String path = "/tokens/verify";

        /**
         * <p> Значение для request param для верификации access token в authorization server.
         * <p> Значение по-умолчанию "accessToken".
         **/
        private String queryParamName = "accessToken";

        @NotNull
        private Cache cache = new Cache();

        @Validated
        @Getter
        @Setter
        public static class Cache {

            /**
             * <p> Значение в секундах, которое определяет сколько будет храниться access token в {@link com.google.common.cache.CacheBuilder} после записи.
             * <p> Значение по-умолчанию 900 секунд.
             * <p> Доступные значения должны быть в диапазоне 1-3600. Не должно быть больше часа из-за требований безопасности.
             * 
             * @see com.google.common.cache.CacheBuilder#expireAfterWrite(Duration)
             * @see org.springframework.cache.concurrent.ConcurrentMapCache
             * @see org.springframework.cache.CacheManager
             **/
            @Min(1)
            @Max(3600)
            private Long expireAfterWriteInSec = 900L;

            /**
             * <p> Значение, которое означает максимум возможных записей в Cache.
             * <p> Значение по-умолчанию 1.000.000.
             * <p> Доступные значения должны быть в диапазоне 1-5.000.000.
             * 
             * @apiNote Обратите внимание на возможное переполнение heap из-за слишком большого размера Cache.
             * @see com.google.common.cache.CacheBuilder#maximumSize(long) 
             * @see org.springframework.cache.concurrent.ConcurrentMapCache
             * @see org.springframework.cache.CacheManager
             **/
            @Min(1)
            @Max(5_000_000)
            private Long size = 1_000_000L;

        }

    }
}