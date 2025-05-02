#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/account.h"

START_TEST(test_account_create_valid_input)
{
    const char *userid = "user123";
    const char *password = "securepassword";
    const char *email = "user@example.com";
    const char *birthdate = "1990-01-01";

    account_t *account = account_create(userid, password, email, birthdate);

    ck_assert_ptr_nonnull(account);
    ck_assert_str_eq(account->userid, userid);
    ck_assert_str_eq(account->email, email);
    ck_assert_str_eq(account->birthdate, birthdate);
    ck_assert_int_le(strlen(account->password_hash), HASH_LENGTH);

    account_free(account);
}
END_TEST

START_TEST(test_account_create_invalid_email)
{
    const char *userid = "user123";
    const char *password = "securepassword";
    const char *email = "invalid email";
    const char *birthdate = "1990-01-01";

    account_t *account = account_create(userid, password, email, birthdate);

    ck_assert_ptr_null(account);
}
END_TEST

START_TEST(test_account_create_invalid_birthdate)
{
    const char *userid = "user123";
    const char *password = "securepassword";
    const char *email = "user@example.com";
    const char *birthdate = "1990-02-30"; // Invalid date

    account_t *account = account_create(userid, password, email, birthdate);

    ck_assert_ptr_null(account);
}
END_TEST

Suite *account_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("account_create()");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_account_create_valid_input);
    tcase_add_test(tc_core, test_account_create_invalid_email);
    tcase_add_test(tc_core, test_account_create_invalid_birthdate);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = account_suite();
    sr = srunner_create(s);

    // Run tests in verbose mode
    srunner_run_all(sr, CK_VERBOSE);

    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}