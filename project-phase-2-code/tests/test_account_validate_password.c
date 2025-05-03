#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/account.h"
#include "../src/logging.h"

// Test valid password
START_TEST(test_valid_password) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    ck_assert(account_validate_password(test_account, "password123") == true);

    account_free(test_account);
}
END_TEST

// Test invalid password
START_TEST(test_invalid_password) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    ck_assert(account_validate_password(test_account, "wrongpassword") == false);

    account_free(test_account);
}
END_TEST

// Test empty password
START_TEST(test_empty_password) {
    account_t *test_account = account_create("testuser", "password123", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    ck_assert(account_validate_password(test_account, "") == false);

    account_free(test_account);
}
END_TEST

Suite *account_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("account_validate_password()");

    // Core test case
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_valid_password);
    tcase_add_test(tc_core, test_invalid_password);
    tcase_add_test(tc_core, test_empty_password);
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