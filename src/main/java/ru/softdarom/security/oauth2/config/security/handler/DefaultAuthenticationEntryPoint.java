package ru.softdarom.security.oauth2.config.security.handler;

import brave.Tracer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Generated;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Generated
public class DefaultAuthenticationEntryPoint extends DefaultExceptionHandler implements AuthenticationEntryPoint {

    public DefaultAuthenticationEntryPoint(ObjectMapper objectMapper, Tracer tracer) {
        super(objectMapper, tracer);
    }

    @Override
    protected HttpStatus getHttpStatus() {
        return HttpStatus.FORBIDDEN;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        doHandle(response, exception);
    }
}