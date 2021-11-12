package ru.softdarom.security.oauth2.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.client.WebClient;
import ru.softdarom.security.oauth2.config.property.ApiKeyProperties;
import ru.softdarom.security.oauth2.config.property.OAuth2Properties;
import ru.softdarom.security.oauth2.dto.OAuth2TokenDto;
import ru.softdarom.security.oauth2.service.AuthHandlerExternalService;

import javax.annotation.PostConstruct;

@RequiredArgsConstructor
public class AuthHandlerExternalServiceImpl implements AuthHandlerExternalService {

    private final ApiKeyProperties apiKeyProperties;
    private final OAuth2Properties oAuth2Properties;

    private WebClient webClient;

    @PostConstruct
    void init() {
        webClient = WebClient.builder()
                .baseUrl(oAuth2Properties.getAuthServer().getHost())
                .defaultHeader(apiKeyProperties.getHeaderName(), apiKeyProperties.getToken().getOutgoing())
                .build();
    }


    @Override
    public ResponseEntity<OAuth2TokenDto> verify(String apiKey, String accessToken) {
        return webClient
                .get()
                .uri(uri -> uri
                        .path(oAuth2Properties.getAuthServer().getPath())
                        .queryParam(oAuth2Properties.getAuthServer().getQueryParamName(), accessToken)
                        .build()
                )
                .retrieve()
                .toEntity(OAuth2TokenDto.class)
                .block();
    }
}