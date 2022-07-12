package ru.softdarom.security.oauth2.config.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ru.softdarom.security.oauth2.dto.base.DefaultRoleType.*;

@Validated
@Getter
@Setter
@ConfigurationProperties(value = "spring.security.qrcheck.roles")
public class RoleProperties {

    /**
     * <p> Роли пользователей используемые для доступа к API через мобильные устройства
     * <p> Стандартные значения: USER, CHECKMAN, PROMOTER
     **/
    private Set<String> mobileRoles = Stream.of(USER, CHECKMAN, PROMOTER).map(Enum::toString).collect(Collectors.toSet());

    /**
     * <p> Сервисные роли для служебного использования в т.ч. для межсерверного взаимодействия
     * <p> Стандартные значения: API_KEY
     **/
    private Set<String> serviceRoles = Set.of(API_KEY.toString());

}
