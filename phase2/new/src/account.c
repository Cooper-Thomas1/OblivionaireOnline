#define _POSIX_C_SOURCE 200809L
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

// Returns true if valid, false if not. If valid, out_len is set to the length to store.
bool validate_email(const char *email, size_t *out_len);

// Returns true if valid, false if not. If valid, out_len is set to the length to store.
bool validate_birthdate(const char *bday, size_t *out_len);

// Hashes password into out_hash (must be at least HASH_LENGTH+1 bytes). Returns true on success.
bool hash_password(const char *pw, char *out_hash, size_t out_hash_len);

// Safe memcpy for fixed-length fields (returns number of bytes copied, or -1 on error).
int safe_memcpy(char *dest, const char *src, size_t max_len);


/**
 * @brief Validates that an email is ASCII printable and contains no spaces.
 *
 * The email must be a null-terminated string of length 1 to EMAIL_LENGTH (inclusive),
 * containing only printable ASCII characters and no spaces.
 *
 * @param email    Null-terminated string to validate.
 * @param out_len  Optional pointer to size_t to receive the length of the validated email (may be NULL).
 * @return true if the email is valid, false otherwise (logs error on failure).
 */
bool validate_email(const char *email, size_t *out_len) {
  size_t len = strnlen(email, EMAIL_LENGTH);
  for (size_t i = 0; i < len; ++i) {
    if (!isprint((unsigned char)email[i]) || isspace((unsigned char)email[i])) {
      log_message(LOG_ERROR, "Invalid email format. Email must be ASCII printable and contain no spaces.");
      return false;
    }
  }
  if (out_len) *out_len = len;
  return true;
}


/**
 * @brief Validates a birthdate string for correct format and calendar validity.
 *
 * The birthdate must be a null-terminated string of exactly BIRTHDATE_LENGTH (10) characters,
 * in the format YYYY-MM-DD, with hyphens in the correct positions and digits elsewhere.
 * The default value "0000-00-00" is allowed. If valid, optionally sets out_len to BIRTHDATE_LENGTH.
 *
 * @param bday    Null-terminated string representing the birthdate to validate.
 * @param out_len Optional pointer to size_t to receive the length of the validated birthdate (may be NULL).
 * @return true if the birthdate is valid, false otherwise (logs error on failure).
 */
bool validate_birthdate(const char *bday, size_t *out_len) {  
  if (strlen(bday) != BIRTHDATE_LENGTH) {
    log_message(LOG_ERROR, "Birthdate must be in the format YYYY-MM-DD.");
    return false;
  }

  if (strcmp(bday, "0000-00-00") == 0) {
    if (out_len) *out_len = BIRTHDATE_LENGTH;
    return true;
  }

  for (int i = 0; i < BIRTHDATE_LENGTH; ++i) {
    if ((i == 4 || i == 7)) {
      if (bday[i] != '-') {
        log_message(LOG_ERROR, "Birthdate format error: missing hyphens.");
        return false;
      }
    } else if (!isdigit((unsigned char)bday[i])) {
      log_message(LOG_ERROR, "Birthdate format error: non-digit characters found.");
      return false;
    }
  } 

  struct tm tm = {0};
  // strptime version (recommended, but may not be available on all platforms e.g. my Windows)
  /*
  if (strptime(bday, "%Y-%m-%d", &tm) == NULL) {
    log_message(LOG_ERROR, "Invalid birthdate format or values.");
    return false;
  }
  */

  // sscanf version (manual parsing, less robust)
  int year, month, day;
  if (sscanf(bday, "%4d-%2d-%2d", &year, &month, &day) != 3) {
    log_message(LOG_ERROR, "Invalid birthdate format or values (sscanf).");
    return false;
  }
  tm.tm_year = year - 1900;
  tm.tm_mon = month - 1;
  tm.tm_mday = day;
  ////

  tm.tm_isdst = -1;
  time_t t = mktime(&tm);
  if (t == -1 || tm.tm_year != year - 1900 || tm.tm_mon != month - 1 || tm.tm_mday != day) {
    log_message(LOG_ERROR, "Invalid birthdate value.");
    return false;
  }

  if (out_len) *out_len = BIRTHDATE_LENGTH;
  return true;
}


/**
 * @brief Hashes the provided password using libsodium Argon2id.
 *
 * This function hashes the given plaintext password using libsodium's Argon2id algorithm
 * and stores the result in the provided output buffer. The output buffer must be at least
 * HASH_LENGTH + 1 bytes to accommodate the null-terminated hash string.
 * 
 * Reference: Password hashing API - Libsodium documentation
 * @ref https://doc.libsodium.org/password_hashing/default_phf
 *
 * @param pw           Null-terminated plaintext password to hash.
 * @param out_hash     Output buffer for the hash (must be at least HASH_LENGTH + 1 bytes).
 * @param out_hash_len Length of the output buffer.
 * @return true on success, false on failure (logs error).
 */
bool hash_password(const char *pw, char *out_hash, size_t out_hash_len) {
  if (out_hash_len < HASH_LENGTH + 1) {
    log_message(LOG_ERROR, "Invalid arguments to hash_password.");
    return false;
  }
  if (sodium_init() < 0) {
    log_message(LOG_ERROR, "Failed to initialise the sodium library.");
    return false;
  }
  if (crypto_pwhash_str_alg(
    out_hash,
    pw,
    strlen(pw),
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_ARGON2ID13
  ) != 0) {
    log_message(LOG_ERROR, "Password hashing failed.");
    return false;
  }
  return true;
}


/**
 * @brief Safely copies up to max_len bytes from src to dest.
 *
 * Copies exactly max_len bytes from src to dest. If max_len is 0,
 * log an error and returns -1. If src and dest overlap, logs an error and returns -1.
 *
 * @param dest    Destination buffer.
 * @param src     Source buffer.
 * @param max_len Maximum number of bytes to copy.
 * @return Number of bytes copied on success, -1 on error.
 */
int safe_memcpy(char *dest, const char *src, size_t max_len) {
    if (max_len <= 0) {
        log_message(LOG_ERROR, "safe_memcpy: Invalid arguments.");
        return -1;
    }
    // Check for overlap
    if ((src < dest && src + max_len > dest) ||
        (dest < src && dest + max_len > src)) {
        log_message(LOG_ERROR, "safe_memcpy: Source and destination buffers overlap.");
        return -1;
    }
    memcpy(dest, src, max_len);
    return (int)max_len;
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
  if (!new_account) {
    log_message(LOG_ERROR, "Memory allocation failed for new account.");
    return NULL;
  }
  sodium_memzero(new_account, sizeof(account_t));

  char hash_buf[HASH_LENGTH+1];
  if (!hash_password(plaintext_password, hash_buf, sizeof(hash_buf))) {
    account_free(new_account);
    return NULL;
  }
  safe_memcpy(new_account->password_hash, hash_buf, HASH_LENGTH);

  size_t email_len;
  if (!validate_email(email, &email_len)) {
    account_free(new_account);
    return NULL;
  }
  safe_memcpy(new_account->email, email, email_len);

  size_t bday_len;
  if (!validate_birthdate(birthdate, &bday_len)) {
    account_free(new_account);
    return NULL;
  }
  safe_memcpy(new_account->birthdate, birthdate, bday_len);

  size_t userid_len = strnlen(userid, USER_ID_LENGTH);
  safe_memcpy(new_account->userid, userid, userid_len);

  new_account->account_id = 0;
  new_account->unban_time = 0;
  new_account->expiration_time = 0;
  new_account->login_count = 0;
  new_account->login_fail_count = 0;
  new_account->last_login_time = 0;
  new_account->last_ip = 0;

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
 * @pre acc and new_plaintext_password must not be NULL.
 * @pre new_plaintext_password must be a valid, null-terminated string.
 *
 * @return true on success, false on failure (with error logged).
 *
 * @note The function securely erases the old password hash before updating.
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  char new_hash_buf[HASH_LENGTH+1];
  if (!hash_password(new_plaintext_password, new_hash_buf, sizeof(new_hash_buf))) {
    return false;
  }
  sodium_memzero(acc->password_hash, HASH_LENGTH);
  safe_memcpy(acc->password_hash, new_hash_buf, HASH_LENGTH);
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
  acc->expiration_time = t;
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
  size_t new_email_len;
  if (!validate_email(new_email, &new_email_len)) {
    return;
  }
  sodium_memzero(acc->email, EMAIL_LENGTH);
  safe_memcpy(acc->email, new_email, new_email_len);
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
  safe_memcpy(safe_userid, acct->userid, USER_ID_LENGTH);
  safe_memcpy(safe_email, acct->email, EMAIL_LENGTH);
  safe_userid[USER_ID_LENGTH] = '\0';
  safe_email[EMAIL_LENGTH] = '\0';

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
  return (size_t)write(fd, outbuf, (size_t)len) == (size_t)len;
}

