package com.company.incidentplatform.incident;

import java.util.List;

/**
 * Standard paginated response envelope enforcing Section 9.1 limits.
 */
public record PagedResponse<T>(
        List<T> content,
        int page,
        int pageSize,
        long totalElements,
        int totalPages,
        boolean last
) {
    public static <T> PagedResponse<T> of(
            List<T> content, int page, int pageSize, long totalElements) {
        int totalPages = pageSize > 0 ? (int) Math.ceil((double) totalElements / pageSize) : 0;
        boolean isLast = page >= totalPages - 1;
        return new PagedResponse<>(content, page, pageSize, totalElements, totalPages, isLast);
    }
}
