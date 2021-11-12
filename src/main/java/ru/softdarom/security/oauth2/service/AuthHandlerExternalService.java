package ru.softdarom.security.oauth2.service;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import ru.softdarom.security.oauth2.dto.OAuth2TokenDto;

public interface AuthHandlerExternalService {

    ResponseEntity<OAuth2TokenDto> verify(@RequestHeader("X-ApiKey-Authorization") String apiKey, @RequestParam String accessToken);

}