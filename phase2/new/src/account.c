#include "account.h"
#include "logging.h"
#include <sodium.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "banned.h"

// Validated inputs go here
typedef struct {
  char email[EMAIL_LENGTH+1];
} email_t;

typedef struct {
  char hash[HASH_LENGTH+1];
} pwhash_t;

typedef struct {
  char date[BIRTHDATE_LENGTH+1];
} birthdate_t;

int safe_strncpy(char *dest, const char *src, size_t dest_size);
email_t *validate_email(const char *email);
pwhash_t *hash_password(const char* pw);
birthdate_t *validate_birthdate(const char *bday);


/**
 * @brief Safely copies a string with guaranteed null-termination.
 *
 * Copies up to dest_size-1 characters from src to dest, always null-terminating dest.
 *
 * @param dest Destination buffer.
 * @param src  Source null-terminated string.
 * @param dest_size Size of the destination buffer.
 * @return 0 on success, -1 if dest_size < 1.
 */
int safe_strncpy(char *dest, const char *src, size_t dest_size) {
  if (dest_size < 1) {
    log_message(LOG_WARN, "Strncpy failed as dest_size < 1.");
    return -1;
  }

  strncpy(dest, src, dest_size -1);
  dest[dest_size-1] = '\0';
  return 0;
}


/**
 * @brief Validates that an email is ASCII printable and contains no spaces.
 *
 * If the email is longer than EMAIL_LENGTH, it will be truncated.
 * 
 * @param email Null-terminated string to validate.
 * @return Pointer to a valid email_t struct on success, NULL on error (logs error).
 */
email_t *validate_email(const char *email) {
  for (const char *p = email; *p != '\0'; p++) {
    if (!isprint((unsigned char)*p) || isspace((unsigned char)*p)) {
      log_message(LOG_ERROR, "Invalid email format. Email must be ASCII printable and contain no spaces.");
      return NULL;
    }
  }

  email_t *valid_email = malloc(sizeof(email_t));
  if (valid_email == NULL) {
    log_message(LOG_ERROR, "Memory allocation failed for valid_email.");
    return NULL;
  }

  safe_strncpy(valid_email->email, email, EMAIL_LENGTH+1);
  return valid_email;
}


/**
 * @brief Hashes the provided password using libsodium library (Argon2)
 * 
 * Reference: Password hashing API - Libsodium documentation
 * @ref https://doc.libsodium.org/password_hashing/default_phf
 * "On POSIX systems, everything in libsodium is guaranteed to be thread-safe."
 *
 * @param pw The plaintext password to be hashed.
 * 
 * @return NULL on fail to hash (with log_message(LOG_ERROR)), else pwhash_t valid_hash. 
 * 
 */
pwhash_t *hash_password(const char* pw) {
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
    valid_hash->hash,
    pw,
    strlen(pw),
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_ARGON2ID13
  ) != 0) {
    log_message(LOG_ERROR, "Password hashing failed.");
    free(valid_hash);
    return NULL;
  }
  return valid_hash;
}


/**
 * @brief Validates a birthdate string for correct format and calendar validity.
 *
 * This function checks that the input string is exactly 10 characters long and matches
 * the format YYYY-MM-DD, with hyphens in the correct positions and digits elsewhere.
 * It then verifies that the date is a valid calendar date (e.g., not 2024-02-30).
 *
 * @param bday A non-NULL, null-terminated string representing the birthdate to validate.
 *             Must be in the format YYYY-MM-DD. The default value "0000-00-00" is allowed.
 *
 * @return A pointer to a heap-allocated birthdate_t structure containing the validated date
 *         on success, or NULL on error (with log_message(LOG_ERROR) called).
 *
 * @note The caller is responsible for freeing the returned structure.
 * @note Returns NULL if the input is NULL, not the correct length, not in the correct format,
 *       or not a valid calendar date.
 */
birthdate_t *validate_birthdate(const char *bday) {  
  if (strlen(bday) != BIRTHDATE_LENGTH) {
    log_message(LOG_ERROR, "Birthdate must be in the format YYYY-MM-DD.");
    return NULL;
  }

  if (strcmp(bday, "0000-00-00") == 0) {
    birthdate_t *default_bday = malloc(sizeof(birthdate_t));
    if (default_bday == NULL) {
      log_message(LOG_ERROR, "Failed to malloc space for default birthdate.");
      return NULL;
    }
    safe_strncpy(default_bday->date, bday, BIRTHDATE_LENGTH + 1);
    return default_bday;
  }

  for (int i = 0; i < BIRTHDATE_LENGTH; ++i) {
    if ((i == 4 || i == 7)) {
      if (bday[i] != '-') {
        log_message(LOG_ERROR, "Birthdate format error: missing hyphens.");
        return NULL;
      }
    } else if (!isdigit((unsigned char)bday[i])) {
      log_message(LOG_ERROR, "Birthdate format error: non-digit characters found.");
      return NULL;
    }
  } 

  char buf[BIRTHDATE_LENGTH + 1];
  safe_strncpy(buf, bday, BIRTHDATE_LENGTH + 1);

  struct tm tm = {0};
  // strptime version (recommended, but may not be available on all platforms e.g. my Windows)
  /*
  if (strptime(buf, "%Y-%m-%d", &tm) == NULL) {
    log_message(LOG_ERROR, "Invalid birthdate format or values.");
    return NULL;
  }
  */

  // sscanf version (manual parsing, less robust)
  int year, month, day;
  if (sscanf(buf, "%4d-%2d-%2d", &year, &month, &day) != 3) {
    log_message(LOG_ERROR, "Invalid birthdate format or values (sscanf).");
    return NULL;
  }
  tm.tm_year = year - 1900;
  tm.tm_mon = month - 1;
  tm.tm_mday = day;
  ////

  tm.tm_isdst = -1;
  if (mktime(&tm) == -1) {
    log_message(LOG_ERROR, "Invalid birthdate value.");
    return NULL;
  }

  birthdate_t *valid_bday = malloc(sizeof(birthdate_t));
  if (valid_bday == NULL) {
    log_message(LOG_ERROR, "Failed to malloc space for valid birthdate.");
    return NULL;
  }  

  safe_strncpy(valid_bday->date, bday, BIRTHDATE_LENGTH+1);
  return valid_bday;
}


/**
 * @brief Creates a new user account with the specified parameters.
 *
 * This function allocates and initialises a new account structure on the heap using the provided
 * user ID, plaintext password, email address, and birthdate. All arguments must be valid,
 * null-terminated strings and none may be NULL. The password is securely hashed using the
 * libsodium Argon2 hashing library. The email is validated to ensure it contains only
 * ASCII printable characters and no spaces. The birthdate is checked for correct format
 * (YYYY-MM-DD) and validity as a calendar date. All other account fields are set to their
 * default values.
 *
 * The caller is responsible for freeing the returned account structure using @ref account_free.
 *
 * @param userid A valid, null-terminated string representing the user ID.
 * @param plaintext_password A valid, null-terminated string representing the plaintext password.
 * @param email A valid, null-terminated string representing the email address (ASCII printable, no spaces).
 * @param birthdate A valid, null-terminated string representing the birthdate in YYYY-MM-DD format.
 *
 * @pre All arguments must be valid, null-terminated strings.
 * @pre None of the pointers may be NULL.
 *
 * @return Pointer to the newly created account structure on success, or NULL on error.
 *         On error, an appropriate error message is logged using log_message.
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

  pwhash_t *hashed_password = hash_password(plaintext_password);
  if (hashed_password == NULL) {
    account_free(new_account);
    return NULL;
  }
  safe_strncpy(new_account->password_hash, hashed_password->hash, HASH_LENGTH + 1);
  free(hashed_password);

  email_t *valid_email = validate_email(email);
  if (!(valid_email)) {
    account_free(new_account);
    return NULL;
  }
  safe_strncpy(new_account->email, valid_email->email, EMAIL_LENGTH + 1);
  free(valid_email);

  birthdate_t *valid_bday = validate_birthdate(birthdate);
  if (!(valid_bday)) {
    account_free(new_account);
    return NULL;
  }
  safe_strncpy(new_account->birthdate, valid_bday->date, BIRTHDATE_LENGTH + 1);
  free(valid_bday);

  new_account->account_id = 0;
  new_account->unban_time = 0;
  new_account->expiration_time = 0;
  new_account->login_count = 0;
  new_account->login_fail_count = 0;
  new_account->last_login_time = 0;
  new_account->last_ip = 0;
  safe_strncpy(new_account->userid, userid, USER_ID_LENGTH+1);

  return new_account;
}


/**
 * @brief Securely frees an account structure.
 *
 * This function securely erases the contents of the given account structure
 * using sodium_memzero() to prevent sensitive data from lingering in memory,
 * then deallocates the memory. If acc is NULL, the function does nothing.
 *
 * @param acc Pointer to an account_t structure allocated by account_create,
 *            or NULL. Must not be freed elsewhere.
 *
 * @note This function does not set the caller's pointer to NULL.
 *       The caller is responsible for doing so if needed.
 */
void account_free(account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_WARN, "Attempted to free a NULL account pointer.");
    return;
  }
  sodium_memzero(acc, sizeof(account_t));
  free(acc);
  log_message(LOG_INFO, "Account memory freed successfully.");
}


/**
 * @brief Verifies if a plaintext password matches the stored password hash.
 *
 * Uses Argon2id via libsodium to securely compare the provided plaintext password
 * against the stored hash in the account structure.
 * @ref https://doc.libsodium.org/password_hashing/default_phf
 *
 * @param acc Pointer to the account structure (must not be NULL).
 * @param plaintext_password Null-terminated string containing the password to verify (must not be NULL).
 *
 * @pre Both @p acc and @p plaintext_password must be non-NULL.
 * @pre @p plaintext_password must be a valid, null-terminated string.
 *
 * @return true if the password matches the stored hash, false otherwise or on error.
 */
bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  int result = crypto_pwhash_str_verify(
    acc->password_hash,
    plaintext_password,
    strlen(plaintext_password)
  );
  return result == 0;
}


/**
 * @brief Securely updates the account's password hash.
 *
 * Hashes the provided new plaintext password using Argon2id (libsodium),
 * securely erases the old password hash, and stores the new hash in the account.
 *
 * @param acc Pointer to the account structure to update (must not be NULL).
 * @param new_plaintext_password Null-terminated string containing the new password (must not be NULL).
 *
 * @pre @p acc and @p plaintext_password must not be NULL.
 * @pre @p plaintext_password must be a valid, null-terminated string.
 *
 * @return true on success, false on failure (with error logged).
 *
 * @note The function securely erases the old password hash before updating.
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  pwhash_t *new_hashed_pw = hash_password(new_plaintext_password);
  if (!(new_hashed_pw)) {
    return false;
  }

  sodium_memzero(acc->password_hash, HASH_LENGTH);    // Erase old pw 
  safe_strncpy(acc->password_hash, new_hashed_pw->hash, HASH_LENGTH);
  free(new_hashed_pw);

  return true;
}


/**
 * @brief Record a successful login for an account.
 *
 * Resets the login failure count to zero, increments the login success count (unless at UINT_MAX),
 * updates the last login time to the current system time, and records the last IP address.
 *
 * @param acc Pointer to the account structure. Must not be NULL.
 * @param ip  IPv4 address from which the login was made.
 *
 * @pre acc must be non-NULL.
 */
void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  acc->login_fail_count = 0;
  if (acc->login_count < UINT_MAX) {
    acc->login_count += 1;
  }
  acc->last_login_time = time(NULL);
  acc->last_ip = ip;
}


/**
 * @brief Record a failed login attempt for an account.
 *
 * Resets the login success count to zero and increments the login failure count (unless at UINT_MAX).
 *
 * @param acc Pointer to the account structure. Must not be NULL.
 *
 * @pre acc must be non-NULL.
 */
void account_record_login_failure(account_t *acc) {
  acc->login_count = 0;
  if (acc->login_fail_count < UINT_MAX) {
    acc->login_fail_count += 1;
  }
}


/**
 * @brief Checks if the account is currently banned.
 *
 * Compares the current system time with the account's unban time.
 * If the current time is earlier than the unban time, the account is considered banned.
 *
 * @param acc A pointer to the account structure to check. Must not be NULL.
 * @pre acc must be non-NULL.
 * @return true if the account is currently banned, false otherwise.
 */
bool account_is_banned(const account_t *acc) {
  if (acc->unban_time > 0) {
    time_t now = time(NULL);
    return (now < acc->unban_time);
  }
  return false;
}


/**
 * @brief Checks if the account is currently expired.
 *
 * Compares the current system time with the account's expiration time.
 * If the current time is earlier than the expiration time, the account is considered expired.
 *
 * @param acc A pointer to the account structure to check. Must not be NULL.
 * @pre acc must be non-NULL.
 * @return true if the account is currently expired, false otherwise.
 */
bool account_is_expired(const account_t *acc) {
  if (acc->expiration_time > 0) {
    time_t now = time(NULL);
    return (now > acc->expiration_time);
  }
  return false;
}


/**
 * @brief Sets the unban time for the given account.
 *
 * @param acc Pointer to the account structure to update. Must not be NULL.
 * @param t   The new unban time as a timestamp.
 */
void account_set_unban_time(account_t *acc, time_t t) {
  acc->unban_time = t;
}


/**
 * @brief Sets the expiration time for the given account.
 *
 * @param acc Pointer to the account structure to update. Must not be NULL.
 * @param t   The new expiration time as a timestamp. 
 */
void account_set_expiration_time(account_t *acc, time_t t) {
  acc->unban_time = t;
}


/**
 * @brief Sets the account's email address after validating it.
 *
 * Validates the new email address for correct format and allowed characters.
 * If valid, updates the account's email field safely.
 *
 * @param acc Pointer to the account structure. Must not be NULL.
 * @param new_email New email address to set. Must be a valid, null-terminated string.
 *
 * @pre acc != NULL
 * @pre new_email != NULL
 */
void account_set_email(account_t *acc, const char *new_email) {
  if (!validate_email(new_email)) {
    return;
  }
  safe_strncpy(acc->email, new_email, EMAIL_LENGTH+1);
}


/**
 * @brief Print a human-readable summary of the account to a file descriptor.
 *
 * Prints a brief summary of the account's current status to the specified file descriptor.
 * The summary includes user ID, email, login statistics (successes, failures), last login time,
 * and last login IP address. Does not print sensitive information such as password hashes.
 *
 * @param acct Pointer to the account structure (must not be NULL).
 * @param fd   File descriptor open for writing (must be valid).
 * @return true on success, false if writing fails.
 *
 * @pre acct != NULL
 * @pre fd is a valid, writable file descriptor
 */
bool account_print_summary(const account_t *acct, int fd) {
  char safe_userid[USER_ID_LENGTH + 1];
  char safe_email[EMAIL_LENGTH + 1];
  safe_strncpy(safe_userid, acct->userid, USER_ID_LENGTH + 1);
  safe_strncpy(safe_email, acct->email, EMAIL_LENGTH + 1);

  char time_buf[64];
  struct tm tm_info;
  if (acct->last_login_time > 0 && localtime_r(&(acct->last_login_time), &tm_info)) {
      strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
  } else {
      snprintf(time_buf, sizeof(time_buf), "Never");
  }

  char ip_buf[INET_ADDRSTRLEN];
  struct in_addr ip_addr;
  ip_addr.s_addr = htonl(acct->last_ip);
  if (!inet_ntop(AF_INET, &ip_addr, ip_buf, sizeof(ip_buf))) {
      snprintf(ip_buf, sizeof(ip_buf), "Unknown");
  }

  char outbuf[512];
  int len = snprintf(outbuf, sizeof(outbuf),
      "----- Account Summary -----\n"
      "User ID: %s\n"
      "Email: %s\n"
      "Login Successes: %u\n"
      "Login Failures: %u\n"
      "Last Login Time: %s\n"
      "Last Login IP: %s\n"
      "--------------------------\n",
      safe_userid,
      safe_email,
      acct->login_count,
      acct->login_fail_count,
      time_buf,
      ip_buf
  );
  if (len < 0) {
    return false;
  }
  return write(fd, outbuf, (size_t)len) == (size_t)len;
}

