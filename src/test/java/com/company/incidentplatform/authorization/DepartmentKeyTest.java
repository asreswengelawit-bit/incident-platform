package com.company.incidentplatform.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import org.junit.jupiter.api.Test;

class DepartmentKeyTest {

    @Test
    void normalizesCaseAndWhitespaceForResponsibilityMatching() {
        assertThat(DepartmentKey.matches(" Finance ", "finance")).isTrue();
        assertThat(DepartmentKey.normalize("  Finance ")).isEqualTo("finance");
    }

    @Test
    void rejectsControlCharactersIncludingAtTheEdges() {
        assertThatIllegalArgumentException().isThrownBy(() -> DepartmentKey.normalize("\tFinance"));
    }

    @Test
    void rejectsDepartmentKeysOverTheIntakeLimit() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> DepartmentKey.normalize("a".repeat(DepartmentKey.MAX_LENGTH + 1)));
    }
}
