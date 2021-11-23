package ru.softdarom.security.oauth2.config.security.handler;

import brave.Tracer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Generated;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Generated
public class DefaultAuthenticationEntryPoint extends DefaultExceptionHandler implements AuthenticationEntryPoint {

    public DefaultAuthenticationEntryPoint(ObjectMapper objectMapper, Tracer tracer) {
        super(objectMapper, tracer);
    }

    @Override
    protected HttpStatus getHttpStatus() {
        return HttpStatus.UNAUTHORIZED;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        if (exception instanceof AuthenticationCredentialsNotFoundException) {
            doHandle(
                    response,
                    new AuthenticationCredentialsNotFoundException("An authentication credentials not found into the request!", exception)
            );
        } else if (exception instanceof InsufficientAuthenticationException) {
            doHandle(response, extractExceptionCause(exception));
        } else {
            doHandle(response, exception);
        }
    }

    private AuthenticationException extractExceptionCause(AuthenticationException exception) {
        if (Objects.nonNull(exception.getCause())) {
            return new InsufficientAuthenticationException(exception.getCause().getMessage(), exception);
        } else {
            return exception;
        }
    }
}