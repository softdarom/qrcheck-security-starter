package ru.softdarom.security.oauth2.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.Generated;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Generated
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    private Long errorId;
    private String message;

    public ErrorResponse(String message) {
        this.message = message;
    }
}