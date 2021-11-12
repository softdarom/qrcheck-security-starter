package ru.softdarom.security.oauth2.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.Generated;
import lombok.NoArgsConstructor;
import ru.softdarom.security.oauth2.dto.base.TokenValidType;

import javax.validation.constraints.NotNull;
import java.util.Set;

@Data
@Generated
@JsonInclude(JsonInclude.Include.NON_NULL)
@NoArgsConstructor
public class OAuth2TokenDto {

    @JsonProperty("user_id")
    private Long userId;

    @JsonProperty("azp")
    private String azp;

    @JsonProperty("aud")
    private String aud;

    @NotNull
    @JsonProperty("sub")
    private String sub;

    @JsonProperty("scopes")
    private Set<String> scopes;

    @JsonProperty("email")
    private String email;

    @JsonProperty("valid")
    private TokenValidType valid;

    public OAuth2TokenDto(TokenValidType valid) {
        this.valid = valid;
    }
}