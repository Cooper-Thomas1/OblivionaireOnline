#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/account.h"
#include "../src/logging.h"

// Test valid email update
START_TEST(test_valid_email) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    const char *valid_email = "new.email@example.com";
    account_set_email(test_account, valid_email);
    ck_assert_str_eq(test_account->email, valid_email);

    account_free(test_account);
}
END_TEST

// Test invalid email with spaces
START_TEST(test_invalid_email_with_spaces) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    const char *invalid_email = "invalid email@example.com";
    account_set_email(test_account, invalid_email);
    ck_assert_str_ne(test_account->email, invalid_email); // Email should remain unchanged

    account_free(test_account);
}
END_TEST

// Test invalid email with non-ASCII characters
START_TEST(test_invalid_email_non_ascii) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    const char *invalid_email = "invalidéemail@example.com";
    account_set_email(test_account, invalid_email);
    ck_assert_str_ne(test_account->email, invalid_email); // Email should remain unchanged

    account_free(test_account);
}
END_TEST

// Test invalid email exceeding max length
START_TEST(test_invalid_email_too_long) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    char invalid_email[EMAIL_LENGTH + 10];
    memset(invalid_email, 'a', sizeof(invalid_email) - 1);
    invalid_email[sizeof(invalid_email) - 1] = '\0';

    account_set_email(test_account, invalid_email);
    ck_assert_str_ne(test_account->email, invalid_email); // Email should remain unchanged

    account_free(test_account);
}
END_TEST

Suite *account_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("account_set_email()");

    // Core test case
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_valid_email);
    tcase_add_test(tc_core, test_invalid_email_with_spaces);
    tcase_add_test(tc_core, test_invalid_email_non_ascii);
    tcase_add_test(tc_core, test_invalid_email_too_long);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = account_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}