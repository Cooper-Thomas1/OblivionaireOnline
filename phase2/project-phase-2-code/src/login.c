#include "login.h"
#include "db.h"
#include "logging.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>


// Helper function to safely write to a file descriptor
void safe_fd_message(int fd, const char *fmt, ...);


/**
 * @brief Safely writes a formatted message to a file descriptor.
 *
 * Formats the message using a bounded buffer and writes it atomically to the given file descriptor.
 * Prevents buffer overflows and format string vulnerabilities.
 *
 * @param fd   File descriptor to write to.
 * @param fmt  printf-style format string.
 * @param ...  Arguments for the format string.
 */
void safe_fd_message(int fd, const char *fmt, ...) {
  char buf[256];
  va_list args;

  va_start(args, fmt);
  int len = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if (len < 0) return;

  size_t count = ((size_t)len < sizeof(buf)) ? (size_t)len : sizeof(buf) - 1;
  write(fd, buf, count);
}


/**
 * @brief Handles user login authentication and session setup.
 *
 * Implements the business logic for user login:
 * - Looks up the account by user ID.
 * - Checks for account ban or expiration.
 * - Checks for excessive failed login attempts.
 * - Validates the supplied password.
 * - Records login success or failure.
 * - Populates the session struct on success.
 * - Sends messages to the client and logs events.
 *
 * @param userid           Null-terminated user ID string (must not be NULL).
 * @param password         Null-terminated password string (must not be NULL).
 * @param client_ip        IPv4 address of the client.
 * @param login_time       Timestamp of the login attempt.
 * @param client_output_fd Writable file descriptor for client messages.
 * @param session          Pointer to session struct to populate on success (must not be NULL).
 * @return                 LOGIN_SUCCESS on success, or appropriate LOGIN_FAIL_* code on failure.
 *
 * @pre userid, password, and session must be non-NULL and valid null-terminated strings.
 * @pre client_output_fd must be a valid, writable file descriptor.
 */
login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session)  
{
  account_t account;
  bool found_account = account_lookup_by_userid(userid, &account);
  if (!found_account) {
    log_message(LOG_INFO, "Login failed: user '%s' not found.", userid);
    safe_fd_message(client_output_fd, "Login failed: user not found.");
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  if (account_is_expired(&account)) {
    log_message(LOG_INFO, "Login failed: account '%s' expired.", userid);
    safe_fd_message(client_output_fd, "Login failed: account expired.");
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  if (account_is_banned(&account)) {
    log_message(LOG_INFO, "Login failed: account '%s' is banned.", userid);
    safe_fd_message(client_output_fd, "Login failed: account is banned.");
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }

  if (account.login_fail_count >= 10) {
    log_message(LOG_WARN, "Login failed: IP temporarily banned for user '%s'.", userid);
    safe_fd_message(client_output_fd, "Login failed: too many failed attempts.");
    return LOGIN_FAIL_IP_BANNED;
  }

  if (!account_validate_password(&account, password)) {
    account_record_login_failure(&account);
    log_message(LOG_INFO, "Login failed: bad password for user '%s'.", userid);
    safe_fd_message(client_output_fd, "Login failed: incorrect password.");
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  account_record_login_success(&account, client_ip);

  if (account.account_id > INT_MAX || account.account_id < INT_MIN) {
    log_message(LOG_ERROR, "Login failed: account ID out of range for user '%s'.", userid);
    safe_fd_message(client_output_fd, "Login failed: internal error.");
    session->account_id = SESSION_INVALID_ACCOUNT_ID;
    return LOGIN_FAIL_INTERNAL_ERROR;
  }
  session->account_id = (int)account.account_id;
  session->session_start = login_time;
  session->expiration_time = account.expiration_time;

  log_message(LOG_INFO, "Login success: user '%s'.", userid);
  safe_fd_message(client_output_fd, "Login successful.");
  return LOGIN_SUCCESS;
}
