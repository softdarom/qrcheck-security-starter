package ru.softdarom.security.oauth2.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import ru.softdarom.security.oauth2.config.property.RoleProperties;
import ru.softdarom.security.oauth2.service.RoleService;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j(topic = "SECURITY")
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleProperties roleProperties;

    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public Set<String> getCurrentRoles() {
        LOGGER.trace("The current role will be returned from SecurityContextHolder");
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        LOGGER.debug("The current authentication is [{}]", authentication);
        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(it -> it.contains(ROLE_PREFIX))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getMobileAbilityRoles() {
        LOGGER.trace("All mobile roles will be returned");
        return roleProperties.getMobileRoles();
    }

    @Override
    public String[] getMobileAbilityRolesAsArray() {
        LOGGER.trace("All mobile roles will be returned as an array");
        return getMobileAbilityRoles().toArray(new String[0]);
    }

    @Override
    public Set<String> getServiceAbilityRoles() {
        LOGGER.trace("All service roles will be returned");
        return roleProperties.getServiceRoles();
    }

    @Override
    public String[] getServiceAbilityRolesAsArray() {
        LOGGER.trace("All service roles will be returned as an array");
        return getServiceAbilityRoles().toArray(new String[0]);
    }
}
