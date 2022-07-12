package ru.softdarom.security.oauth2.config;

import brave.Tracer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import ru.softdarom.security.oauth2.config.property.ApiKeyProperties;
import ru.softdarom.security.oauth2.config.property.AuthServerProperties;
import ru.softdarom.security.oauth2.config.property.OAuth2Properties;
import ru.softdarom.security.oauth2.config.property.RoleProperties;
import ru.softdarom.security.oauth2.config.security.ApiKeyAuthorizationConfig;
import ru.softdarom.security.oauth2.config.security.CacheRemoteOAuth2TokenService;
import ru.softdarom.security.oauth2.config.security.CustomAuthenticationProvider;
import ru.softdarom.security.oauth2.config.security.handler.DefaultAccessDeniedHandler;
import ru.softdarom.security.oauth2.config.security.handler.DefaultAuthenticationEntryPoint;
import ru.softdarom.security.oauth2.service.AuthExternalService;
import ru.softdarom.security.oauth2.service.RoleService;
import ru.softdarom.security.oauth2.service.impl.AuthExternalServiceImpl;
import ru.softdarom.security.oauth2.service.impl.RoleServiceImpl;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Configuration
@EnableConfigurationProperties(
        {
                ApiKeyProperties.class,
                OAuth2Properties.class,
                AuthServerProperties.class,
                RoleProperties.class
        }
)
@ConditionalOnClass(
        {
                ResourceServerTokenServices.class,
                EnableResourceServer.class,
                CacheManager.class,
                AuthenticationProvider.class,
                Tracer.class,
                ObjectMapper.class,
                Authentication.class,
                PreAuthenticatedAuthenticationToken.class
        }
)
@ConditionalOnProperty(prefix = "spring.security.qrcheck", name = "enabled", matchIfMissing = true)
@Slf4j(topic = "SECURITY")
public class QRCheckSecurityAutoConfiguration {

    @Bean(name = "qrCheckAuthenticationProvider")
    @ConditionalOnMissingBean(value = CustomAuthenticationProvider.class, name = "qrCheckAuthenticationProvider")
    AuthenticationProvider qrCheckAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean(name = "qrCheckAuthenticationEntryPoint")
    @ConditionalOnMissingBean(value = AuthenticationEntryPoint.class)
    @ConditionalOnBean(value = {ObjectMapper.class, Tracer.class})
    AuthenticationEntryPoint defaultAuthenticationEntryPoint(ObjectMapper objectMapper, Tracer tracer) {
        return new DefaultAuthenticationEntryPoint(objectMapper, tracer);
    }

    @Bean(name = "qrCheckAccessDeniedHandler")
    @ConditionalOnMissingBean(value = AccessDeniedHandler.class)
    @ConditionalOnBean(value = {ObjectMapper.class, Tracer.class})
    AccessDeniedHandler defaultAccessDeniedHandler(ObjectMapper objectMapper, Tracer tracer) {
        return new DefaultAccessDeniedHandler(objectMapper, tracer);
    }

    @Bean(name = "qrCheckCacheRemoteOAuth2TokenService")
    @ConditionalOnMissingBean(value = ResourceServerTokenServices.class)
    @ConditionalOnBean(value = AuthenticationProvider.class, name = "qrCheckAuthenticationProvider")
    @ConditionalOnProperty(prefix = "spring.security.qrcheck.oauth2", name = "enabled", matchIfMissing = true)
    ResourceServerTokenServices cacheRemoteOAuth2TokenService(AuthExternalService defaultAuthExternalService) {
        return new CacheRemoteOAuth2TokenService(defaultAuthExternalService);
    }

    @Bean("defaultAuthExternalService")
    @ConditionalOnMissingBean(value = AuthExternalService.class)
    AuthExternalService authExternalService(AuthServerProperties authServerProperties, WebClient qrWebClient) {
        return new AuthExternalServiceImpl(qrWebClient, authServerProperties);
    }

    @Bean("qrCheckWebClient")
    @ConditionalOnMissingBean(value = WebClient.class)
    public WebClient defaultWebClient(ApiKeyProperties apiKeyProperties, AuthServerProperties authServerProperties) {
        return WebClient.builder()
                .baseUrl(authServerProperties.getHost())
                .defaultHeader(apiKeyProperties.getHeaderName(), apiKeyProperties.getToken().getOutgoing())
                .build();
    }

    @Primary
    @Bean(name = "qrCheckOAuth2CacheManager")
    @ConditionalOnMissingBean(name = "oAuth2CacheManager")
    @ConditionalOnProperty(prefix = "spring.security.qrcheck.oauth2", name = "enabled", matchIfMissing = true)
    CacheManager oAuth2CacheManager(OAuth2Properties oAuth2Properties) {
        return new ConcurrentMapCacheManager() {
            @Override
            protected Cache createConcurrentMapCache(String name) {
                return new ConcurrentMapCache(
                        name,
                        CacheBuilder.newBuilder()
                                .maximumSize(oAuth2Properties.getCache().getSize())
                                .expireAfterWrite(oAuth2Properties.getCache().getExpireAfterWriteInSec(), TimeUnit.SECONDS)
                                .build()
                                .asMap(),
                        false);
            }
        };
    }

    @Bean(name = "qrCheckApiKeyExternalAuthorizationFilter")
    @ConditionalOnMissingBean(value = ApiKeyAuthorizationConfig.ApiKeyAuthorizationFilter.class)
    @ConditionalOnProperty(prefix = "spring.security.qrcheck.api-key", name = "enabled", havingValue = "true")
    AbstractPreAuthenticatedProcessingFilter apiKeyExternalAuthorizationFilter(
            ApiKeyProperties properties,
            AuthExternalService defaultAuthExternalService,
            @Value("${spring.application.name}") String springApplicationName
    ) {
        var filter = new ApiKeyAuthorizationConfig.ApiKeyAuthorizationFilter(properties.getHeaderName());
        filter.setAuthenticationManager(authentication -> {
            var credentials = Optional.ofNullable(authentication.getCredentials()).map(Object::toString).orElse(null);
            var serviceName = Optional.ofNullable(properties.getToken().getServiceName()).orElse(springApplicationName);
            var incoming =
                    defaultAuthExternalService.getIncomingTokens(serviceName)
                            .stream()
                            .map(UUID::toString)
                            .collect(Collectors.toSet());
            if (StringUtils.hasText(credentials) && incoming.contains(credentials)) {
                LOGGER.info("Success external authentication by ApiKey: '{}'", credentials);
                return new ApiKeyAuthorizationConfig.ApiKeyAuthentication(credentials);
            } else {
                throw new BadCredentialsException("The API key was not an expected value.");
            }
        });
        return filter;
    }

    @Bean(name = "defaultRoleService")
    @ConditionalOnMissingBean(value = RoleService.class)
    RoleService defaultRoleService(RoleProperties roleProperties) {
        return new RoleServiceImpl(roleProperties);
    }
}