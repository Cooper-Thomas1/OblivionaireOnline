#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/account.h"
#include "../src/logging.h"

// Test updating password with a valid new password
START_TEST(test_update_valid_password) {
    account_t *test_account = account_create("testuser", "oldpassword", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    const char *new_password = "newpassword123";
    ck_assert(account_update_password(test_account, new_password) == true);
    ck_assert(account_validate_password(test_account, new_password) == true);

    account_free(test_account);
}
END_TEST

// Test updating password with an empty string
START_TEST(test_update_empty_password) {
    account_t *test_account = account_create("testuser", "oldpassword", "test@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(test_account);

    // ASSUMPTION: emptry string is a valid, null-terminated string
    const char *empty_password = "";
    ck_assert(account_update_password(test_account, empty_password) == true);

    account_free(test_account);
}
END_TEST


Suite *account_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("account_update_password()");

    // Core test case
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_update_valid_password);
    tcase_add_test(tc_core, test_update_empty_password);
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