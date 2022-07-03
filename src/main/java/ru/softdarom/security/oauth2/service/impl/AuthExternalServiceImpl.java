package ru.softdarom.security.oauth2.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.web.reactive.function.client.WebClient;
import ru.softdarom.security.oauth2.config.property.AuthServerProperties;
import ru.softdarom.security.oauth2.dto.OAuth2TokenDto;
import ru.softdarom.security.oauth2.service.AuthExternalService;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class AuthExternalServiceImpl implements AuthExternalService {

    private final WebClient webClient;
    private final AuthServerProperties authServerProperties;

    @Override
    public OAuth2TokenDto verify(String accessToken) {
        return webClient
                .get()
                .uri(uri -> uri
                        .path(authServerProperties.getVerifyPath())
                        .queryParam(authServerProperties.getAccessTokenQueryParamName(), accessToken)
                        .build()
                )
                .retrieve()
                .toEntity(OAuth2TokenDto.class)
                .block()
                .getBody();
    }

    @Override
    public Set<UUID> getIncomingTokens(String serviceName) {
        return webClient
                .get()
                .uri(uri -> uri
                        .path(authServerProperties.getIncomingApiKeysPath())
                        .queryParam(authServerProperties.getServiceNameQueryParamName(), serviceName)
                        .build()
                )
                .retrieve()
                .toEntityFlux(UUID.class)
                .block()
                .getBody()
                .collect(Collectors.toSet())
                .block();
    }

    @Override
    public UUID getOutgoingToken(String serviceName) {
        return webClient
                .get()
                .uri(uri -> uri
                        .path(authServerProperties.getOutgoingApiKeysPath())
                        .queryParam(authServerProperties.getServiceNameQueryParamName(), serviceName)
                        .build()
                )
                .retrieve()
                .toEntity(UUID.class)
                .block()
                .getBody();
    }
}
