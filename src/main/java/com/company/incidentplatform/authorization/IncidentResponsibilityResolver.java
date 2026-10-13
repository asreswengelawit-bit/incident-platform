package com.company.incidentplatform.authorization;

import com.company.incidentplatform.identity.AppUserEntity;
import com.company.incidentplatform.identity.AppUserRepository;
import com.company.incidentplatform.security.PlatformRole;
import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.security.RolePermissions;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentResponsibilityResolver {

    private final AppUserRepository users;
    private final ObjectMapper objectMapper;

    public IncidentResponsibilityResolver(AppUserRepository users, ObjectMapper objectMapper) {
        this.users = users;
        this.objectMapper = objectMapper;
    }

    public boolean leadsDepartment(PlatformUser user, String department) {
        return leadsDepartment(user.permissions().ledDepartments(), department);
    }

    public static boolean leadsDepartment(Iterable<String> ledDepartments, String department) {
        String key = DepartmentKey.normalize(department);
        if (key == null) {
            return false;
        }
        for (String led : ledDepartments) {
            if (DepartmentKey.matches(led, key)) {
                return true;
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public List<UUID> resolve(PlatformRole role, String department) {
        if (role == PlatformRole.SECURITY_ADMIN) {
            return users.findByActiveTrueAndRole_Name(role).stream().map(AppUserEntity::getId).toList();
        }
        if (role != PlatformRole.SECURITY_LEAD) {
            throw new IllegalArgumentException("Notification recipient role is not allowed: " + role);
        }
        String key = DepartmentKey.normalize(department);
        if (key == null) {
            return List.of();
        }
        return users.findByActiveTrueAndRole_Name(PlatformRole.SECURITY_LEAD).stream()
                .filter(user -> {
                    RolePermissions permissions = RolePermissions.fromJson(
                            user.getRole().permissionsJson(objectMapper));
                    return leadsDepartment(permissions.ledDepartments(), key);
                })
                .map(AppUserEntity::getId)
                .toList();
    }
}
