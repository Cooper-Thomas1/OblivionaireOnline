#include "account.h"

// Added for testing purposes
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  account_t *new_account = malloc(sizeof(account_t));
  if (new_account == NULL) {
    fprintf(stderr, "Error: Memory allocation failed for new account.\n");
    return NULL;
  }

  memset(new_account, 0, sizeof(account_t)); // Zeros all values

  //assign userid
  strncpy(new_account->userid, userid, USER_ID_LENGTH - 1);
  new_account->userid[USER_ID_LENGTH - 1] = '\0'; // Null termination

  // need to call hashing function and set password.
  
  // Validate email
  for (const char *p = email; *p != '\0'; p++) {
    if (!isprint((unsigned char)*p) || isspace((unsigned char)*p)) {
        fprintf(stderr, "Error: Invalid email format. Email must be ASCII printable and contain no spaces.\n");
        free(new_account);
        return NULL;
    }
  }

  //assign email address
  strncpy(new_account->email, email, EMAIL_LENGTH - 1);
  new_account->email[EMAIL_LENGTH - 1] = '\0';
  //assign birthdate

  //check if birthdate is valid
  int year, month, day;
  if (sscanf(birthdate, "%4d-%2d-%2d", &year, &month, &day) != 3 ||
      year < 1900 || year > 2025 ||
      month < 1 || month > 12) {
    fprintf(stderr, "Error: Invalid birthdate format. Expected YYYY-MM-DD.\n");
    free(new_account);
    return NULL;
  }

  int days_in_month[] = { 31, (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  
  if (day < 1 || day > days_in_month[month - 1]) {
    fprintf(stderr, "Error: Invalid day for birthdate month.\n");
    free(new_account);
    return NULL;
  }

  strncpy(new_account->birthdate, birthdate, BIRTHDATE_LENGTH);

  // NOTE: 1990-01-01 is 10 chars long, so would be 11 with null terminator.
  new_account->birthdate[BIRTHDATE_LENGTH] = '\0';

  return new_account;
}


void account_free(account_t *acc) {
  if (acc == NULL) {
    return;
  }
  memset(acc, 0, sizeof(account_t)); // Zeros all values
  free(acc);
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) ip;
}

void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}

bool account_is_banned(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_email(account_t *acc, const char *new_email) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_email;
}

bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void) acct;
  (void) fd;
  return false;
}

