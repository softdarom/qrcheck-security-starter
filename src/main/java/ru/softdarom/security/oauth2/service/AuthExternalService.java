package ru.softdarom.security.oauth2.service;

import ru.softdarom.security.oauth2.dto.OAuth2TokenDto;

import java.util.Set;
import java.util.UUID;

public interface AuthExternalService {

    OAuth2TokenDto verify(String accessToken);

    Set<UUID> getIncomingTokens(String serviceName);

    UUID getOutgoingToken(String serviceName);
}