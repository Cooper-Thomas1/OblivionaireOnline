#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h> 

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
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) plaintext_password;
  (void) email;
  (void) birthdate;

  return NULL;
}


void account_free(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
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
  acc->login_fail_count = 0;
  acc->login_count += 1;
  acc->last_login_time = time(NULL);
  acc->last_ip = ip;
}

void account_record_login_failure(account_t *acc) {
  acc->login_count = 0;
  acc->login_fail_count += 1;
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
  char safe_userid[USER_ID_LENGTH + 1];
  char safe_email[EMAIL_LENGTH + 1];

  memcpy(safe_userid, acct->userid, USER_ID_LENGTH);
  safe_userid[USER_ID_LENGTH] = '\0';

  memcpy(safe_email, acct->email, EMAIL_LENGTH);
  safe_email[EMAIL_LENGTH] = '\0';

  // format last login time
  char time_buf[64];
  struct tm tm_info;
  if (localtime_r(&(acct->last_login_time), &tm_info) != NULL) {
      strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
  } else {
      snprintf(time_buf, sizeof(time_buf), "Unknown");
  }

  // format IP address
  char ip_buf[INET_ADDRSTRLEN];
  struct in_addr ip_addr;
  ip_addr.s_addr = htonl(acct->last_ip);
  if (inet_ntop(AF_INET, &ip_addr, ip_buf, sizeof(ip_buf)) == NULL) {
      snprintf(ip_buf, sizeof(ip_buf), "Invalid");
  }

  // print summary
  int written = dprintf(fd,
      "----- Account Summary -----\n"
      "User ID: %s\n"
      "Email: %s\n"
      "Login Successes: %u\n"
      "Login Failures: %u\n"
      "Last Login Time: %s\n"
      "Last Login IP: %s\n"
      "----------------------------\n",
      safe_userid,
      safe_email,
      acct->login_count,
      acct->login_fail_count,
      time_buf,
      ip_buf
  );

  return written >= 0;
}
