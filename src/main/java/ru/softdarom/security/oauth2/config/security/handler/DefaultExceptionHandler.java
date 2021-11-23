package ru.softdarom.security.oauth2.config.security.handler;

import brave.Tracer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Generated;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import ru.softdarom.security.oauth2.dto.response.ErrorResponse;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Generated
public abstract class DefaultExceptionHandler {

    private static final String DEFAULT_TRACE_ID_HEADER_NAME = "X-B3-TraceId";
    private static final String DEFAULT_SPAN_ID_HEADER_NAME = "X-B3-SpanId";

    private final ObjectMapper objectMapper;
    private final Tracer tracer;

    protected DefaultExceptionHandler(ObjectMapper objectMapper, Tracer tracer) {
        this.objectMapper = objectMapper;
        this.tracer = tracer;
    }

    protected abstract HttpStatus getHttpStatus();

    protected void doHandle(HttpServletResponse response, RuntimeException exception) throws IOException {
        doHandle(response, exception, getHttpStatus());
    }

    protected void doHandle(HttpServletResponse response, RuntimeException exception, HttpStatus httpStatus) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(httpStatus.value());
        var traceId = tracer.currentSpan().context().traceIdString();
        var spanId = tracer.currentSpan().context().spanIdString();
        response.setHeader(DEFAULT_TRACE_ID_HEADER_NAME, traceId);
        response.setHeader(DEFAULT_SPAN_ID_HEADER_NAME, spanId);
        response.getWriter().write(objectMapper.writeValueAsString(new ErrorResponse(exception.getMessage())));
    }
}