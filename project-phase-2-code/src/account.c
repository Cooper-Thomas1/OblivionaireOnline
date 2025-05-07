#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h> 
#include <stdlib.h>
#include <ctype.h>
#include <sodium.h> 



int safe_strcpy(char *dest, const char *src, size_t dest_size) {
  if (dest == NULL || src == NULL || dest_size < 1) {
    log_message(LOG_ERROR, "Strncpy failed as src/dest is NULL, or dest_size < 1.");
    return -1;
  }

  strncpy(dest, src, dest_size -1);
  dest[dest_size-1] = '\0';
  return 0;
}

int parse_int(const char *str, int len) {
  char buf[5]; // long enough for each part of date
  if (len >= sizeof(buf)) {
    log_message(LOG_ERROR, "Birthday length exceeds buffer size.");
    return -1;
  }
  safe_strcpy(buf, str, len);
  buf[len] = '\0';
  char *end;
  long val = strtol(buf, &end, 10);
  if (*end != '\0') {
    log_message(LOG_ERROR, "Invalid character in date string.");
    return -1}; // invalid character
  return (int)val;
}

typedef struct{
  char userid[USER_ID_LENGTH];
} userid_t;


userid_t *validate_userid(const char *userid) {
  if (strlen(userid) >= USER_ID_LENGTH) {
    log_message(LOG_ERROR, "Userid exceeds maximum length.");
    return NULL;
  }

  if (userid[0] == '\0') {
    log_message(LOG_ERROR,"User ID cannot be empty.");
    return NULL;
  }

  for (const char *p = userid; *p != '\0'; p++) {
    if (!isprint((unsigned char)*p) || isspace((unsigned char)*p)) {
      log_message(LOG_ERROR, "Invalid userid format. userid must be ASCII printable and contain no spaces.");
      return NULL;
    }
  }

  userid_t *valid_userid = malloc(sizeof(userid_t));
  if (valid_userid == NULL) {
    log_message(LOG_ERROR, "Memory allocation failed for valid_userid.");
    return NULL;
  }

  safe_strcpy(valid_userid->userid, userid, USER_ID_LENGTH);

  return valid_userid;
}



typedef struct {
  char hash[HASH_LENGTH];
} pwhash_t;

pwhash_t *hash_password(const char* pw) {
  // Initialise sodium library
  if (sodium_init() < 0) {
    log_message(LOG_ERROR, "Failed to initialise the sodium library.");
    return NULL;
  }

  pwhash_t *valid_hash = malloc(sizeof(pwhash_t));
  if (valid_hash == NULL) {
    log_message(LOG_ERROR, "Failed to allocate memory for password hash.");
    return NULL;
  }


  if (crypto_pwhash_str_alg(
    valid_hash->hash,                     // Output buffer for hash
    pw,                                   // password to hash from param
    strlen(pw),                           // Length of password 
    crypto_pwhash_OPSLIMIT_INTERACTIVE,   // CPU cost, safe default
    crypto_pwhash_MEMLIMIT_INTERACTIVE,   // Memory cost, safe default
    crypto_pwhash_ALG_ARGON2ID13          // alogorithm: Argon2id v1.3
  ) != 0) {
    log_message(LOG_ERROR, "Password hashing failed.");
    free(valid_hash);
    return NULL;
  }

  return valid_hash;
}

typedef struct {
  char date[BIRTHDATE_LENGTH];
} birthdate_t;


birthdate_t *validate_birthdate(const char *bday) {  
  for (int i = 0; i < BIRTHDATE_LENGTH; i++) {
    if (!isdigit((unsigned char)bday[i])) {
      log_message(LOG_ERROR, "Birthdate must contain only digits");
      return NULL;
    }
  }
  
  int year = parse_int(bday, 4); 
  int month = parse_int(bday + 4, 2);
  int day = parse_int(bday + 6, 2);
  if (year < 1900 || month < 1 || month > 12) {
    log_message(LOG_ERROR, "Invalid year or month for birthdate.");
    return NULL;
  }

  int days_in_month[] = { 31, (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

  if (day < 1 || day > days_in_month[month - 1]) {
    log_message(LOG_ERROR, "Invalid day for birthdate month.");
    return NULL;
  }

  struct tm input_tm = {0};
  input_tm.tm_year = year - 1900;
  input_tm.tm_mon = month - 1;
  input_tm.tm_mday = day;

  time_t input_time = mktime(&input_tm);
  if (input_time == -1 || difftime(input_time, time(NULL)) > 0) {
    log_message(LOG_ERROR, "Birthdate cannot be in the future.");
    return NULL;
  }

  birthdate_t *valid_bday = malloc(sizeof(birthdate_t));
  if (valid_bday == NULL) {
    log_message(LOG_ERROR, "Failed to malloc space for valid bday.");
    return NULL;
  }  

  safe_strcpy(valid_bday->date, bday, BIRTHDATE_LENGTH);
  return valid_bday;
}

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
    log_message(LOG_ERROR, "Memory allocation failed for new account.");
    return NULL;
  }

  sodium_memzero(new_account, sizeof(account_t));

  userid_t *valid_userid = validate_userid(userid);
  if (!(valid_userid)) {
    account_free(new_account);
    return NULL;
  }
  safe_strcpy(new_account->userid, valid_userid->userid, USER_ID_LENGTH);
  free(valid_userid);

  if ( plaintext_password[0] == '\0' ) {
    log_message(LOG_ERROR, "Password cannot be empty.");
    account_free(new_account);
    return NULL;
  }

  for (const char *p = plaintext_password; *p != '\0'; p++) {
    if (!isprint((unsigned char)*p) || isspace((unsigned char)*p)) {
      log_message(LOG_ERROR, "Invalid password format. Password must be ASCII printable and contain no spaces.");
      free(new_account);
      return NULL;
    }
  }

  pwhash_t *hashed_password = hash_password(plaintext_password);
  if (hashed_password == NULL) {
    account_free(new_account);
    return NULL;
  }
  safe_strcpy(new_account->password_hash, hashed_password->hash, HASH_LENGTH);
  free(hashed_password);

  account_set_email(new_account, email);

  birthdate_t *valid_bday = validate_birthdate(birthdate);
  if (!(valid_bday)) {
    account_free(new_account);
    return NULL;
  }
  safe_strcpy(new_account->birthdate, valid_bday->date, BIRTHDATE_LENGTH);
  free(valid_bday);

  return new_account;
}


void account_free(account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_WARN, "Attempted to free a NULL account.");
    return;
  }
  sodium_memzero(acc, sizeof(account_t));// Zeros all values
  free(acc);
  log_message(LOG_INFO, "Account freed successfully.");
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
  
  if (acc->login_count < UINT_MAX) {
    acc->login_count += 1;
  }
  
  acc->last_login_time = time(NULL);
  acc->last_ip = ip;
}

void account_record_login_failure(account_t *acc) {
  acc->login_count = 0;
  
  if (acc->login_fail_count < UINT_MAX) {
    acc->login_fail_count += 1;
  }
}

bool account_is_banned(const account_t *acc) {
  if (acc->unban_time > 0) {
    time_t now = time(NULL);
    return (now < acc->unban_time);
  }
}

bool account_is_expired(const account_t *acc) {
  if (acc->expiration_time > 0) {
    time_t now = time(NULL);
    return (now > acc->expiration_time);
  }
}

void account_set_unban_time(account_t *acc, time_t t) {
  if (t >= 0) {
    acc->unban_time = t;
  } else {
    log_message(LOG_ERROR, "Provided a negative number for unban time.");
  }
}

void account_set_expiration_time(account_t *acc, time_t t) {
  if (t >= 0) {
    acc->expiration_time = t;
  } else {
    log_message(LOG_ERROR, "Provided a negative number for expiration time.");
  }
}

void account_set_email(account_t *acc, const char *new_email) {
  size_t len = strlen(new_email);

  if (len > 0 && new_email[len - 1] == '\n') {
    len--;
  }

  if (len >= EMAIL_LENGTH) {
    len = EMAIL_LENGTH - 1;
  }

  for (size_t i = 0; i < len; i++) {
    if (!isprint((unsigned char)new_email[i]) || isspace((unsigned char)new_email[i])) {
      log_message(LOG_ERROR, "Provided email contains invalid characters.");
      return;
    }
  }

  const char *at = memchr(new_email, '@', len);
  if (!at || at == new_email) {
    log_message(LOG_ERROR, "Email must contain '@' and not start with it.");
    return;
  }

  const char *dot = memchr(at, '.', len - (at - new_email));
  if (!dot || dot == at + 1 || dot >= new_email + len - 1) {
    log_message(LOG_ERROR, "Email domain must contain a '.' after '@'.");
    return;
  }

  memset(acc->email, 0, EMAIL_LENGTH);
  strncpy(acc->email, new_email, len);
  acc->email[len] = '\0';
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
