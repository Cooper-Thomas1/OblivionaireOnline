#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/account.h"

START_TEST(test_account_free_null_pointer) {
    // Test freeing a NULL pointer
    account_free(NULL);
    // No crash or error is expected
    ck_assert_msg(1, "account_free(NULL) should not crash.");
}
END_TEST

START_TEST(test_account_free_valid_account) {
    // Allocate and initialize a valid account_t structure
    account_t *account = malloc(sizeof(account_t));
    ck_assert_ptr_nonnull(account); // Ensure allocation succeeded

    // Fill the structure with dummy data
    memset(account, 0xAA, sizeof(account_t));

    // Call account_free
    account_free(account);

    // No crash or error is expected
    // Since the memory is freed, we cannot directly check its contents,
    // but we ensure no invalid memory access occurs.
    ck_assert_msg(1, "account_free(valid account) should not crash.");
}
END_TEST

Suite *account_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("account_free()");
    tc_core = tcase_create("Core");

    // Add test cases to the test case
    tcase_add_test(tc_core, test_account_free_null_pointer);
    tcase_add_test(tc_core, test_account_free_valid_account);

    // Add the test case to the suite
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = account_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE); // Run tests in verbose mode
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}