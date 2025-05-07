#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h> 
#include <limits.h>
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

// Generated hashes go in here
typedef struct {
  char hash[HASH_LENGTH];
} pwhash_t;

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

/** 
 * @brief: Check if birthdate is valid. The birthdate must be in the format YYYY-MM-DD. 
 *
 * The birthdate must be validated to ensure it is a valid date 
 * in the correct format (YYYY-MM-DD). The year must be within 
 * reasonable range (e.g., 1900-2025), and the day must be 
 * valid for the given month, accounting for leap years.
 * 
 * @param bday in format YYYY-MM-DD to be validated.
 * 
 * @return birthdate_t in format YYYYMMDD (without dashes), or NULL on error.
 */
birthdate_t *validate_birthdate(const char *bday) {  
  int year, month, day;
  if (sscanf(bday, "%4d-%2d-%2d", &year, &month, &day) != 3 ||
    year < 1900 || year > 2025 ||
    month < 1 || month > 12) {
    log_message(LOG_ERROR, "Invalid birthdate format. Expected YYYY-MM-DD.");
    return NULL;
  }
  
  int days_in_month[] = { 31, (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  
  if (day < 1 || day > days_in_month[month - 1]) {
    log_message(LOG_ERROR, "Invalid day for birthdate month.");
    return NULL;
  }

  birthdate_t *valid_bday = malloc(sizeof(birthdate_t));
  if (valid_bday == NULL) {
    log_message(LOG_ERROR, "Failed to malloc space for valid bday.");
    return NULL;
  }  

  snprintf(valid_bday->date, BIRTHDATE_LENGTH, "%04d%02d%02d", year, month, day); // YYYYMMDD format
  return valid_bday;
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

//   // --------- USER ID ---------

//   //checks for valid user id
//   if (userid[0] == '\0') {
//     log_message(LOG_ERROR,"User ID cannot be empty.");
//     free(new_account);
//     return NULL;
//   }

//   //assign userid
//   strncpy(new_account->userid, userid, USER_ID_LENGTH - 1);
//   new_account->userid[USER_ID_LENGTH - 1] = '\0'; // Null termination

//   // -------- PASSWORD ---------

//   // Check if password is empty
//   if (plaintext_password[0] == '\0') {
//     log_message(LOG_ERROR,"Password cannot be empty.");
//     free(new_account);
//     return NULL;
//   }
//   // need to call hashing function and set password.
  
//   // -------- EMAIL ---------

//   // Check if email is empty
//   if (email[0] == '\0') {
//     log_message(LOG_ERROR,"Email cannot be empty.");
//     free(new_account);
//     return NULL;
// }
//   // Validate email is ASCII printable and contains no spaces
//   for (const char *p = email; *p != '\0'; p++) {
//     if (!isprint((unsigned char)*p) || isspace((unsigned char)*p)) {
//         log_message(LOG_ERROR,"Email contains invalid characters.");
//         free(new_account);
//         return NULL;
//     }
//   }

//   //assign email address
//   strncpy(new_account->email, email, EMAIL_LENGTH - 1);
//   new_account->email[EMAIL_LENGTH - 1] = '\0'; 

//   // -------- BIRTHDATE ---------

//   //check if birthdate is valid
//   int year, month, day;
//   if (strlen(birthdate) != 8 || sscanf(birthdate, "%4d%2d%2d", &year, &month, &day) != 3 ||
//       year < 1900 || year > 2025 ||
//       month < 1 || month > 12) {
//     log_message(LOG_ERROR,"Invalid birthdate format. Expected YYYYMMDD.");
//     free(new_account);

  pwhash_t *hashed_password = hash_password(plaintext_password);
  if (hashed_password == NULL) {
    account_free(new_account);
    return NULL;
  }
  safe_strcpy(new_account->password_hash, hashed_password->hash, HASH_LENGTH);
  free(hashed_password);

  // Checks for valid day of month (with leap year consideration)
  // int days_in_month[] = { 31, (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  
  // if (day < 1 || day > days_in_month[month - 1]) {
  //   log_message(LOG_ERROR,"Invalid day for birthday month.");
  //   free(new_account);

  email_t *validated_email = validate_email(email);
  if (validated_email == NULL) {
    account_free(new_account);
    return NULL;
  }
  safe_strcpy(new_account->email, validated_email->email, EMAIL_LENGTH);
  free(validated_email);

  // //assign birthdate
  // strncpy(new_account->birthdate, birthdate, BIRTHDATE_LENGTH);
  // new_account->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

  // log_message(LOG_INFO, "Account created for user ID: %s", new_account->userid);

  birthdate_t *valid_bday = validate_birthdate(birthdate);
  if (!(valid_bday)) {
    account_free(new_account);
    return NULL;
  }
  safe_strcpy(new_account->birthdate, valid_bday->date, BIRTHDATE_LENGTH);
  free(valid_bday);

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

/**
 * @brief Checks whether the plaintext password matches the stored hash.
 * 
 * Uses Argon2id from <libsodium.h> for secure crypto library functionality.
 * Check whether supplied password is correct. returns true on success, false on failure
 * @ref https://doc.libsodium.org/password_hashing/default_phf
 * 
 * @param acc The account to check against.
 * @param plaintext_password The password to check, and should be transmitted over a secure channel.
 * 
 * @pre acc and plaintext_password must be non-NULL.
 * @pre plaintext_password must be a valid, null-terminating string.
 * 
 * @return True if password matches, False if not or on error. 
 * 
 */
bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  /**
   * CODE DESIGN:
   * Hash plaintext password (done in crypto_pwhash_str_verify)
   * Verify a valid password is stored in acc->password_hash (done in crypto_pwhash_str_verify)
   * Lock account (thread-safety)
   * Compare to hash on file -> return true if same, false if not (done in crypto_pwhash_str_verify)
   * Unlock account mutex
   */

  int result = 0;
  result = crypto_pwhash_str_verify(
    acc->password_hash,         // Hash on store
    plaintext_password,         // User inputed pw
    strlen(plaintext_password)  // Input length
  );

  return result == 0;
}

/**
 * @brief Hash a new password and update the account accordingly.
 * 
 * This is similar in structure to account_validate_password,
 * but involves generating a new hash instead of comparing one.
 * Sets hashed password record derived from new plaintext password.
 * 
 * @param acc The account where the password is being updated.
 * @param new_plaintext_password The password to be hashed and updated.
 * 
 * @pre acc and new_plaintext_password must not be NULL.
 * @pre new_plaintext password must be a valid, null-terminated string.
 * 
 * @return true on success, false on failure
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  /**
   * CODE DESIGN:
   * Hash new plaintext password using hash_password, push into validated_hash struct
   * Erase old hash using secure library call sodium_memzero() for acc->hash_password
   * safely write in new hash
   * return true
   */

  pwhash_t *new_hashed_pw = hash_password(new_plaintext_password);
  if (!(new_hashed_pw)) {
    return false;
  }

  sodium_memzero(acc->password_hash, HASH_LENGTH);    // Erase old pw 
  safe_strcpy(acc->password_hash, new_hashed_pw->hash, HASH_LENGTH);
  free(new_hashed_pw);

  return true;
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

/**
 * @brief Checks if the account is currently banned.
 * 
 * This function checks whether the account is banned by comparing the current time
 * with the unban time. If the current time is earlier than the unban time, the account
 * is considered banned.
 * 
 * @param acc A pointer to the account struct to check.
 * 
 * @return true if the account is banned, false otherwise. 
 */
bool account_is_banned(const account_t *acc) {
  if (acc->unban_time > 0) {
    time_t now = time(NULL);
    return (now < acc->unban_time);
  }
  return false;
}

/**
 * @brief Checks if the account has expired.
 * 
 * This function checks whether the account has expired by comparing the current time
 * with the expiration time. If the current time is later than the expiration time, 
 * the account is considered expired.
 * 
 * @param acc A pointer to the account struct to check.
 * 
 * @return true if the account has expired, false otherwise.
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
 * This function updates the unban time of the specified account. If the provided time 
 * is negative, it logs an error and does not update the unban time.
 * 
 * @param acc A pointer to the account struct where the unban time will be set.
 * @param t The new unban time as a timestamp. A negative value will log an error.
 * 
 * @return void
 */
void account_set_unban_time(account_t *acc, time_t t) {
  if (t >= 0) {
    acc->unban_time = t;
  } else {
    log_message(LOG_ERROR, "Provided a negative number for unban time.");
  }
}

/**
 * @brief Sets the expiration time for the given account.
 * 
 * This function updates the expiration time of the specified account. If the provided 
 * time is negative, it logs an error and does not update the expiration time.
 * 
 * @param acc A pointer to the account struct where the expiration time will be set.
 * @param t The new expiration time as a timestamp. A negative value will log an error.
 * 
 * @return void
 */
void account_set_expiration_time(account_t *acc, time_t t) {
  if (t >= 0) {
    acc->expiration_time = t;
  } else {
    log_message(LOG_ERROR, "Provided a negative number for expiration time.");
  }
}

/**
<<<<<<< HEAD
 * @brief Sets the email address for the given account.
 * 
 * This function validates and updates the email address for the specified account. 
 * It ensures that the email address follows basic formatting rules (e.g., contains 
 * an '@' symbol and a '.' in the domain part) and does not exceed the allowed length.
 * It also clears any previously stored email before copying the new one.
 * 
 * @param acc A pointer to the account struct where the email will be updated.
 * @param new_email A string containing the new email address to set.
 * 
 * @return void
 */
// void account_set_email(account_t *acc, const char *new_email) {
//   size_t len = strlen(new_email);

//   if (len > 0 && new_email[len - 1] == '\n') {
//     len--;
//   }

//   if (len >= EMAIL_LENGTH) {
//     len = EMAIL_LENGTH - 1;
//   }

//   for (size_t i = 0; i < len; i++) {
//     if (!isprint((unsigned char)new_email[i]) || isspace((unsigned char)new_email[i])) {
//       log_message(LOG_ERROR, "Provided email contains invalid characters.");
//       return;
//     }
//   }

//   const char *at = memchr(new_email, '@', len);
//   if (!at || at == new_email) {
//     log_message(LOG_ERROR, "Email must contain '@' and not start with it.");
//     return;
//   }

//   const char *dot = memchr(at, '.', len - (at - new_email));
//   if (!dot || dot == at + 1 || dot >= new_email + len - 1) {
//     log_message(LOG_ERROR, "Email domain must contain a '.' after '@'.");
//     return;
//   }
  
//   sodium_memzero(acc->email, EMAIL_LENGTH);
//   strncpy(acc->email, new_email, len);
//   acc->email[len] = '\0';

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
