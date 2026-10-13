package com.company.incidentplatform.authorization;

import java.util.Locale;

public final class DepartmentKey {

    public static final int MAX_LENGTH = 120;

    private DepartmentKey() {
    }

    public static String normalize(String department) {
        String validated = validate(department);
        if (validated == null) {
            return null;
        }
        return validated.toLowerCase(Locale.ROOT);
    }

    public static String validate(String department) {
        if (department == null) {
            return null;
        }
        if (department.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Department must be at most 120 characters and contain no control characters");
        }
        String trimmed = department.trim();
        if (trimmed.isBlank()) {
            return null;
        }
        if (trimmed.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("Department must be at most 120 characters and contain no control characters");
        }
        return trimmed;
    }

    public static boolean matches(String first, String second) {
        String normalizedFirst = normalize(first);
        return normalizedFirst != null && normalizedFirst.equals(normalize(second));
    }
}
