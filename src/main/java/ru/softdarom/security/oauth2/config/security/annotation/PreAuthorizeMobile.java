package ru.softdarom.security.oauth2.config.security.annotation;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAnyRole(@defaultRoleService.getMobileAbilityRolesAsArray)")
public @interface PreAuthorizeMobile {
}
