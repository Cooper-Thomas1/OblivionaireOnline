#define _GNU_SOURCE
#include "account.h"
#include <stdio.h>
#include <unistd.h>

#ifdef TEST_1
int main(void) {
    account_t *acc = account_create(
        "testuser",
        "TestPassword123!",
        "test@example.com",
        "2000-01-01"
    );

    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }

    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }

    if (account_validate_password(acc, "TestPassword123!")) {
        dprintf(STDOUT_FILENO, "Password validation succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password validation failed.\n");
    }

    if (account_update_password(acc, "NewPassword456!")) {
        dprintf(STDOUT_FILENO, "Password updated.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password update failed.\n");
    }

    if (account_validate_password(acc, "NewPassword456!")) {
        dprintf(STDOUT_FILENO, "New password validation succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "New password validation failed.\n");
    }

    account_set_email(acc, "newemail@example.com");
    account_print_summary(acc, STDOUT_FILENO);

    account_free(acc);

    return 0;
}
#endif // test_1

#ifdef TEST_2   // empty password
int main(void) {
    account_t *acc = account_create(
        "testuser",
        "",
        "test@example.com",
        "2000-01-01"
    );
    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }
    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }
    if (account_validate_password(acc, "")) {
        dprintf(STDOUT_FILENO, "Password validation succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password validation failed.\n");
    }
    if (account_update_password(acc, "")) {
        dprintf(STDOUT_FILENO, "Password updated.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password update failed.\n");
    }
    if (account_validate_password(acc, "")) {
        dprintf(STDOUT_FILENO, "New password validation succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "New password validation failed.\n");
    }
    static int login_attempts = 0;

    account_record_login_success(acc, 127001);
     if (acc->login_count == 1) {
        dprintf(STDOUT_FILENO, "Login success recorded.\n");
    } else {
        dprintf(STDOUT_FILENO, "Failed to record login success.\n");
    }
    account_set_email(acc, "newemail@example.com");
    account_print_summary(acc, STDOUT_FILENO);
    account_free(acc);
    return 0;
}
#endif // test_2