package ru.softdarom.security.oauth2.service;

import java.util.Set;

public interface RoleService {

    Set<String> getCurrentRoles();

    Set<String> getMobileAbilityRoles();

    String[] getMobileAbilityRolesAsArray();

    Set<String> getServiceAbilityRoles();

    String[] getServiceAbilityRolesAsArray();

}
