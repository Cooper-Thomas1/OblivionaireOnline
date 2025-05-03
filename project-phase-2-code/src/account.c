#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h> 
#include <stdlib.h>
#include <ctype.h>
#include <sodium.h> // dependency for password hashing


/**
 * @brief safe strncpy wrapper for proper '\0' termination.
 * 
 * @param dest The destination buffer.
 * @param src The source string (@pre: must be NULL-terminated)
 * @param dest_size The size of the destination buffer.
 * 
 * @return 0 = succes, -1 = src/dest is NULL, or dest_size < 1
 */
int safe_strcpy(char *dest, const char *src, size_t dest_size) {
  if (dest == NULL || src == NULL || dest_size < 1) {
    log_message(LOG_ERROR, "Strncpy failed as src/dest is NULL, or dest_size < 1.");
    return -1;
  }

  strncpy(dest, src, dest_size -1);
  dest[dest_size-1] = '\0';
  return 0;
}

// Validated emails go in here
typedef struct {
  char email[EMAIL_LENGTH];
} email_t;

/** 
 * @brief Validate email helper function
 * 
 * This function checks if the email provided is "consisting
 * of only ASCII, printable characters (according to the C standard)
 * and must not contain any spaces".
 * 
 * @param email A valid, null-terminated string representing the email address to validate.
 * 
 * @return A pointer to a valid email_t structure on success, 
 * or NULL on error with log_message(LOG_ERROR).
 */
email_t *validate_email(const char *email) {
  if (strlen(email) >= EMAIL_LENGTH) {
    log_message(LOG_ERROR, "Email exceeds maximum length.");
    return NULL;
  }

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

  safe_strcpy(valid_email->email, email, EMAIL_LENGTH);

  return valid_email;
}


/**
 * @brief Creates a new user account with the specified parameters.
 *
 * This function initialises a dynamically allocated account structure with the given user ID, 
 * hashed password, email address, and birthdate. Other fields are set to their default values.
 * The password is securely hashed, and the caller is responsible for freeing the allocated memory 
 * using `account_free`.
 *
 * @param userid A valid, null-terminated string representing the user ID. Must not be NULL.
 * @param plaintext_password A valid, null-terminated string representing the plaintext password. Must not be NULL.
 * @param email A valid, null-terminated string representing the email address. Must not be NULL. 
 *              The email must consist only of ASCII printable characters and must not contain spaces.
 * @param birthdate A valid, null-terminated string representing the birthdate in the format YYYY-MM-DD. Must not be NULL.
 *
 * @pre All arguments must be valid, null-terminated strings.
 * @pre None of the pointers may be NULL.
 *
 * @return A pointer to the newly created account structure on success, or NULL on error.
 *         On error, an appropriate error message is logged using `log_message`.
 *
 * @note The birthdate is validated to ensure it is in the correct format and represents a valid date.
 *       The email undergoes basic validation to ensure it meets the specified criteria.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  /** FUNCTION PROPOSED DESIGN:
  * NOT NEEDED ---> Validate input params for NULL, emptry string; 
  * Allocate memory for new_acc struct, check for fail (NULL);
  * Initialise all fields -> 0;
  * Copy and validate userid;
  * hash password (via Argon2) -> set password_hash;
  * Validate email -> set email;
  * Validate birth date -> set birthdate;
  * NOT NEEDED ---> Set default values for other fields unban_time, expiration_time, login_count, login_fail_count, last_login_time, last_ip;
  * Return pointer new_acc struct; 
  */


  account_t *new_account = malloc(sizeof(account_t));
  if (new_account == NULL) {
    log_message(LOG_ERROR, "Memory allocation failed for new account.");
    return NULL;
  }

  memset(new_account, 0, sizeof(account_t)); 

  /** Hash password using Argon2
  * Reference: Password hashing API - Libsodium documentation
  * https://doc.libsodium.org/password_hashing/default_phf
  * 
  * sodium_init() - Initialise the sodium library (is MT-Safe. Must be called before any other function.)
  * crypto_pwhash_str_alg() - Hash the password using Argon2id algorithm (is MT-Safe)
  * 
  * FROM https://doc.libsodium.org/internals:
  * "On POSIX systems, everything in libsodium is guaranteed to be thread-safe."
  * 
  * @rubric: The password must be hashed securely (see Section 3.4, “Password handling”)
  * 
  */

  // Initialise sodium library
  if (sodium_init() < 0) {
    log_message(LOG_ERROR, "Failed to initialise the sodium library.");
    account_free(new_account);
    return NULL;
  }

  char buf[HASH_LENGTH];
  if (crypto_pwhash_str_alg(
    buf,                                  // Output buffer for hash
    plaintext_password,                   // password to hash from param
    strlen(plaintext_password),           // Length of password 
    crypto_pwhash_OPSLIMIT_INTERACTIVE,   // CPU cost, safe default
    crypto_pwhash_MEMLIMIT_INTERACTIVE,   // Memory cost, safe default
    crypto_pwhash_ALG_ARGON2ID13          // alogorithm: Argon2id v1.3
  ) != 0) {
    log_message(LOG_ERROR, "Password hashing failed.");
    account_free(new_account);
    return NULL;
  }

  // NOTE: maybe we should check if safe_strcpy fails 
  safe_strcpy(new_account->password_hash, buf, HASH_LENGTH);

  /** Validate email 
   *
   * @rubric: "...A basic check should be performed on the email: it should
   *          consist only of ASCII, printable characters (according to the C standard) and must not contain
   *          any spaces. (Other portions of the system will require the user to verify that they can read
   *          messages sent to that email address.)"
   */

  email_t *validated_email = validate_email(email);
  if (validated_email == NULL) {
    account_free(new_account);
    return NULL;
  }

  safe_strcpy(new_account->email, validated_email->email, EMAIL_LENGTH);
  free(validated_email);

  /** Validate birthdate
   * 
   * @brief: The birthdate must be in the format YYYY-MM-DD. 
   * 
   * The new_account->birthdate field is a string of length BIRTHDATE_LENGTH. 
   * By default, this is 10, thus the birthdate string must be 9 characters long + `\0` terminator.
   * new_account->birthdate @format: YYYYMMDD (without dashes).
   *
   * @rubric: The birthdate must be validated to ensure it is a valid date 
   *         in the correct format (YYYY-MM-DD). The year must be within 
   *         a reasonable range (e.g., 1900-2025), and the day must be 
   *         valid for the given month, accounting for leap years.
   */

  // Check if birthdate is valid
  int year, month, day;
  if (sscanf(birthdate, "%4d-%2d-%2d", &year, &month, &day) != 3 ||
    year < 1900 || year > 2025 ||
    month < 1 || month > 12) {
    log_message(LOG_ERROR, "Invalid birthdate format. Expected YYYY-MM-DD.");
    account_free(new_account);
    return NULL;
  }

  int days_in_month[] = { 31, (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  
  if (day < 1 || day > days_in_month[month - 1]) {
    log_message(LOG_ERROR, "Invalid day for birthdate month.");
    account_free(new_account);
    return NULL;
  }

  snprintf(new_account->birthdate, BIRTHDATE_LENGTH, "%04d%02d%02d", year, month, day);  

  safe_strcpy(new_account->userid, userid, USER_ID_LENGTH);
  new_account->unban_time = 0;
  new_account->expiration_time = 0;
  new_account->login_count = 0;
  new_account->login_fail_count = 0;
  new_account->last_login_time = 0;
  new_account->last_ip = 0;
  return new_account;
}

/**
 * @brief Releases any memory associated with account_t structure.
 *
 * This function deallocates the memory used by the account structure and sets the pointer to NULL.
 * It also zeroes out the contents of the structure before freeing it to ensure sensitive information
 * is not left in memory.
 * 
 * In some cases, memset() can be optimised away by the compiler,
 * So it is important to use functions like sodium_memzero() that are 
 * guaranteed to not be optimised away, to securely erase memory.
 * 
 * @param acc A pointer to the account structure to be freed. Must not be NULL.
 *
 * @return NULL after freeing the account structure.
 */
void account_free(account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_WARN, "Attempted to free a NULL account pointer.");
    return;
  }
  sodium_memzero(acc, sizeof(account_t)); // Securely zeroes memory
  free(acc);
  log_message(LOG_INFO, "Account memory freed successfully.");
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

/**
 * @brief Safely update the account's email address.
 * 
 * This function updates the email address of the account structure
 * and ensures that the new email is properly null-terminated.
 * Thread-safe and secure against buffer overflows.
 * 
 * @param acc A pointer to the account structure to be updated. Must not be NULL.
 * @param new_email The new email address to set for the account. Must be a valid, 
 *                  null-terminated string. Must not be NULL. 
 * 
 * @pre acc, new_email != NULL
 * @pre new_email must be a valid, null-terminated string.
 * 
 * @return log_message(LOG_ERROR,) on invalid email format. From `validate_email`
 */
void account_set_email(account_t *acc, const char *new_email) {
  /**
   * CODE DESIGN:
   * Validate email format;
   * If invalid, log error and return;
   * Lock acc for thread safety; (maybe need)?
   * With the lock held, copy new_email to acc->email;
   * 
   */

  email_t *valid_new_email = validate_email(new_email);
  if (valid_new_email == NULL) {
    return;
  }

  // May need to add thread-locking? 
  safe_strcpy(acc->email, valid_new_email->email, EMAIL_LENGTH);
  free(valid_new_email);
}

bool account_print_summary(const account_t *acct, int fd) {
  (void) acct;
  (void) fd;
  return false;
  // char safe_userid[USER_ID_LENGTH + 1];
  // char safe_email[EMAIL_LENGTH + 1];

  // memcpy(safe_userid, acct->userid, USER_ID_LENGTH);
  // safe_userid[USER_ID_LENGTH] = '\0';

  // memcpy(safe_email, acct->email, EMAIL_LENGTH);
  // safe_email[EMAIL_LENGTH] = '\0';

  // // format last login time
  // char time_buf[64];
  // struct tm tm_info;
  // if (localtime_r(&(acct->last_login_time), &tm_info) != NULL) {
  //     strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
  // } else {
  //     snprintf(time_buf, sizeof(time_buf), "Unknown");
  // }

  // // format IP address
  // char ip_buf[INET_ADDRSTRLEN];
  // struct in_addr ip_addr;
  // ip_addr.s_addr = htonl(acct->last_ip);
  // if (inet_ntop(AF_INET, &ip_addr, ip_buf, sizeof(ip_buf)) == NULL) {
  //     snprintf(ip_buf, sizeof(ip_buf), "Invalid");
  // }

  // // print summary
  // int written = dprintf(fd,
  //     "----- Account Summary -----\n"
  //     "User ID: %s\n"
  //     "Email: %s\n"
  //     "Login Successes: %u\n"
  //     "Login Failures: %u\n"
  //     "Last Login Time: %s\n"
  //     "Last Login IP: %s\n"
  //     "----------------------------\n",
  //     safe_userid,
  //     safe_email,
  //     acct->login_count,
  //     acct->login_fail_count,
  //     time_buf,
  //     ip_buf
  // );

  // return written >= 0;
}
