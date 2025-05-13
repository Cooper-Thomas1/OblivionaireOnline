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

#ifdef TEST_3   // empty all fields
int main(void) {
    account_t *acc = account_create(
        "",
        "",
        "",
        "0000-00-00"
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
    account_set_email(acc, "");
    account_print_summary(acc, STDOUT_FILENO);
    account_free(acc);
    return 0;
}   
#endif // test_3

#ifdef TEST_4   // test future date
int main(void) {
    account_t *acc = account_create(
        "",
        "",
        "",
        "2026-01-01"
    );
    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }
    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }
    account_free(acc);
    return 0;
}
#endif // test_4

#ifdef TEST_5   // test past date
int main(void) {
    account_t *acc = account_create(
        "",
        "",
        "",
        "1800-01-01"
    );
    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }
    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }
    account_free(acc);
    return 0;
}
#endif // test_5

#ifdef TEST_6   // test max email length
int main(void) {
    account_t *acc = account_create(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage",
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage",
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage",
        "2000-01-01"
    );
    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }
    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }
    account_free(acc);
    return 0;
}
#endif // test_6

#ifdef TEST_7   // test incorrect birthdate day
int main(void) {
    account_t *acc = account_create(
        "",
        "",
        "",
        "2000-11-31"
    );
    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }
    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }
    account_free(acc);
    return 0;
}
#endif // test_7

#ifdef TEST_8
int main(void) {    // test all functions
    dprintf(STDOUT_FILENO, "=== Begin comprehensive account tests ===\n");

    // 1. Create account with valid data
    account_t *acc = account_create("alice", "S3cureP@ss!", "alice@example.com", "1990-05-15");
    if (!acc) {
        dprintf(STDOUT_FILENO, "Account creation failed.\n");
        return 1;
    } else {
        dprintf(STDOUT_FILENO, "Account created successfully.\n");
    }

    // 2. Print summary
    account_print_summary(acc, STDOUT_FILENO);

    // 3. Validate correct password
    if (account_validate_password(acc, "S3cureP@ss!")) {
        dprintf(STDOUT_FILENO, "Password validation (correct) succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password validation (correct) failed.\n");
    }

    // 4. Validate incorrect password
    if (!account_validate_password(acc, "wrongpass")) {
        dprintf(STDOUT_FILENO, "Password validation (incorrect) correctly failed.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password validation (incorrect) incorrectly succeeded.\n");
    }

    // 5. Update password and validate
    if (account_update_password(acc, "N3wP@ssword!")) {
        dprintf(STDOUT_FILENO, "Password updated successfully.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password update failed.\n");
    }
    if (account_validate_password(acc, "N3wP@ssword!")) {
        dprintf(STDOUT_FILENO, "New password validation succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "New password validation failed.\n");
    }

    // 6. Set and print new email
    account_set_email(acc, "alice2@example.com");
    dprintf(STDOUT_FILENO, "Updated email:\n");
    account_print_summary(acc, STDOUT_FILENO);

    // 7. Record login success
    account_record_login_success(acc, 0x7F000001); // 127.0.0.1
    dprintf(STDOUT_FILENO, "After login success:\n");
    account_print_summary(acc, STDOUT_FILENO);

    // 8. Record login failure
    account_record_login_failure(acc);
    dprintf(STDOUT_FILENO, "After login failure:\n");
    account_print_summary(acc, STDOUT_FILENO);

    // 9. Ban and expire account, then check status
    time_t now = time(NULL);
    account_set_unban_time(acc, now + 60); // ban for 60 seconds
    account_set_expiration_time(acc, now - 60); // expired 60 seconds ago

    if (account_is_banned(acc)) {
        dprintf(STDOUT_FILENO, "Account is currently banned.\n");
    } else {
        dprintf(STDOUT_FILENO, "Account is not banned.\n");
    }
    if (account_is_expired(acc)) {
        dprintf(STDOUT_FILENO, "Account is expired.\n");
    } else {
        dprintf(STDOUT_FILENO, "Account is not expired.\n");
    }

    // 10. Set invalid email (should not update)
    account_set_email(acc, "bad email with spaces");
    dprintf(STDOUT_FILENO, "After attempting to set invalid email:\n");
    account_print_summary(acc, STDOUT_FILENO);

    // 11. Free account
    account_free(acc);
    dprintf(STDOUT_FILENO, "Account freed.\n");

    // 12. Edge case: create account with empty fields
    account_t *acc2 = account_create("", "", "", "0000-00-00");
    if (acc2) {
        dprintf(STDOUT_FILENO, "Account with empty fields created.\n");
        account_print_summary(acc2, STDOUT_FILENO);
        account_free(acc2);
    } else {
        dprintf(STDOUT_FILENO, "Account with empty fields creation failed (expected for some implementations).\n");
    }

    // 13. Edge case: invalid birthdate
    account_t *acc3 = account_create("bob", "pw", "bob@example.com", "2024-02-30");
    if (!acc3) {
        dprintf(STDOUT_FILENO, "Account creation with invalid birthdate correctly failed.\n");
    } else {
        dprintf(STDOUT_FILENO, "Account creation with invalid birthdate incorrectly succeeded.\n");
        account_free(acc3);
    }

    dprintf(STDOUT_FILENO, "=== End comprehensive account tests ===\n");
    return 0;
}
#endif // test_8

#ifdef TEST_DIABOLICAL
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include "account.h"
#define MAX_TIME_T ((time_t)(~(time_t)0 >> 1))

int main(void) {
    dprintf(STDOUT_FILENO, "=== Begin DIABOLICAL account tests (safe preconditions) ===\n");

    // 1. Overlong but null-terminated strings
    char long_userid[USER_ID_LENGTH + 100];
    char long_email[EMAIL_LENGTH + 100];
    char long_pw[HASH_LENGTH + 100];
    char long_birth[BIRTHDATE_LENGTH + 100];
    memset(long_userid, 'A', sizeof(long_userid) - 1); long_userid[sizeof(long_userid) - 1] = '\0';
    memset(long_email, 'B', sizeof(long_email) - 1); long_email[sizeof(long_email) - 1] = '\0';
    memset(long_pw, 'C', sizeof(long_pw) - 1); long_pw[sizeof(long_pw) - 1] = '\0';
    memset(long_birth, '1', sizeof(long_birth) - 1); long_birth[sizeof(long_birth) - 1] = '\0';

    account_t *acc = account_create(long_userid, long_pw, long_email, long_birth);
    if (!acc) dprintf(STDOUT_FILENO, "Correctly failed to create account with overlong fields.\n");
    else { dprintf(STDOUT_FILENO, "Account created with overlong fields (should not happen).\n"); account_free(acc); }

    // 2. Empty strings
    account_t *acc2 = account_create("", "", "", "");
    if (!acc2) dprintf(STDOUT_FILENO, "Correctly failed to create account with empty fields.\n");
    else { dprintf(STDOUT_FILENO, "Account created with empty fields (should not happen).\n"); account_free(acc2); }

    // 3. Invalid but null-terminated birthdates
    const char *bad_dates[] = {
        "2024-02-30", "2000-13-01", "2000-00-00", "abcd-ef-gh", "9999-99-99", "2000-11-31", "0000-00-00"
    };
    for (size_t i = 0; i < sizeof(bad_dates)/sizeof(bad_dates[0]); ++i) {
        account_t *tmp = account_create("evil", "pw", "evil@example.com", bad_dates[i]);
        if (!tmp) dprintf(STDOUT_FILENO, "Birthdate '%s' correctly rejected.\n", bad_dates[i]);
        else { dprintf(STDOUT_FILENO, "Birthdate '%s' accepted (may be allowed for 0000-00-00).\n", bad_dates[i]); account_free(tmp);}
    }

    // 4. Invalid but null-terminated emails
    const char *bad_emails[] = {
        "bad email", "bad\temail@example.com", "bad\nemail@example.com", "bad@email@domain", "a@b", "a b@c.com"
    };
    for (size_t i = 0; i < sizeof(bad_emails)/sizeof(bad_emails[0]); ++i) {
        account_t *tmp = account_create("user", "pw", bad_emails[i], "2000-01-01");
        if (!tmp) dprintf(STDOUT_FILENO, "Email '%s' correctly rejected.\n", bad_emails[i]);
        else { dprintf(STDOUT_FILENO, "Email '%s' incorrectly accepted.\n", bad_emails[i]); account_free(tmp);}
    }

    // 5. Password edge cases
    account_t *acc3 = account_create("user", "", "user@example.com", "2000-01-01");
    if (acc3) {
        dprintf(STDOUT_FILENO, "Account with empty password created.\n");
        if (account_validate_password(acc3, "")) dprintf(STDOUT_FILENO, "Empty password validated.\n");
        if (account_update_password(acc3, "")) dprintf(STDOUT_FILENO, "Empty password updated.\n");
        account_free(acc3);
    }

    // 6. Stress test: create and free many accounts
    for (int i = 0; i < 1000; ++i) {
        char uid[32];
        snprintf(uid, sizeof(uid), "user%d", i);
        account_t *tmp = account_create(uid, "pw", "stress@example.com", "2000-01-01");
        if (tmp) account_free(tmp);
    }

    // 7. Set fields to extreme values
    account_t *acc4 = account_create("max", "pw", "max@example.com", "2000-01-01");
    if (acc4) {
        acc4->login_count = UINT_MAX;
        acc4->login_fail_count = UINT_MAX;
        acc4->last_login_time = MAX_TIME_T;
        acc4->last_ip = 0xFFFFFFFF;
        acc4->unban_time = MAX_TIME_T;
        acc4->expiration_time = MAX_TIME_T;
        account_print_summary(acc4, STDOUT_FILENO);
        account_record_login_success(acc4, 0xFFFFFFFF);
        account_record_login_failure(acc4);
        account_free(acc4);
    }

    // 8. Print summary to invalid fd (but valid pointer)
    account_t *acc5 = account_create("fd", "pw", "fd@example.com", "2000-01-01");
    if (acc5) {
        account_print_summary(acc5, -1);
        account_free(acc5);
    }

    // 9. Ban/expire logic
    account_t *acc6 = account_create("ban", "pw", "ban@example.com", "2000-01-01");
    if (acc6) {
        time_t now = time(NULL);
        account_set_unban_time(acc6, now + 100000);
        account_set_expiration_time(acc6, now - 100000);
        if (account_is_banned(acc6)) dprintf(STDOUT_FILENO, "Account is banned as expected.\n");
        if (account_is_expired(acc6)) dprintf(STDOUT_FILENO, "Account is expired as expected.\n");
        account_free(acc6);
    }

    // 10. Try to set invalid emails after creation
    account_t *acc7 = account_create("setmail", "pw", "setmail@example.com", "2000-01-01");
    if (acc7) {
        account_set_email(acc7, "bad email with spaces");
        account_set_email(acc7, "bad\t@email.com");
        account_set_email(acc7, "");
        account_print_summary(acc7, STDOUT_FILENO);
        account_free(acc7);
    }

    dprintf(STDOUT_FILENO, "=== End DIABOLICAL account tests (safe preconditions) ===\n");
    return 0;
}
#endif // TEST_DIABOLICAL

#ifdef TEST_9
int main(void) {
    account_t *acc = account_create(
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage",
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage",
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage",
        "2000-01-01"
    );
    if (!acc) {
        dprintf(STDOUT_FILENO, "Failed to create account.\n");
        return 1;
    }
    if (!account_print_summary(acc, STDOUT_FILENO)) {
        dprintf(STDOUT_FILENO, "Failed to print account summary.\n");
    }
    if (account_validate_password(acc, "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890garbage")) {
        dprintf(STDOUT_FILENO, "Password validation succeeded.\n");
    } else {
        dprintf(STDOUT_FILENO, "Password validation failed.\n");
    }
    account_free(acc);
    return 0;
}
#endif // test_9

int main(void) // all empty fields
{
    account_t *acc = account_create(
        "",
        "",
        "",
        ""
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
    account_record_login_success(acc, 127001);
     if (acc->login_count == 1) {
        dprintf(STDOUT_FILENO, "Login success recorded.\n");
    } else {
        dprintf(STDOUT_FILENO, "Failed to record login success.\n");
    }
    account_set_email(acc, "");
    account_print_summary(acc, STDOUT_FILENO);
    account_free(acc);
    return 0;
}