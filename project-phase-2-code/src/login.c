#include "login.h"
#include "account.h"
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd, int log_fd,
                            login_session_data_t *session) 
{
  // Lookup user by ID
  account_t *acc = account_lookup_by_userid(userid);
  if (acc == NULL) {
    dprintf(log_fd, "Login failed: user '%s' not found\n", userid);
    dprintf(client_output_fd, "Login failed: user not found\n");
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  // Check if acc is expired
  if (account_is_expired(acc)) {
    dprintf(log_fd, "Login failed: account '%s' expired\n", userid);
    dprintf(client_output_fd, "Login failed: account expired\n");
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  // Check if acc is banned
  if (account_is_banned(acc)) {
    dprintf(log_fd, "Login failed: account '%s' is banned\n", userid);
    dprintf(client_output_fd, "Login failed: account is banned\n");
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }

  // Check for 10 consecutive login fails
  if (acc->login_fail_count >= 10) {
    dprintf(log_fd, "Login failed: IP temporarily banned for user '%s'\n", userid);
    dprintf(client_output_fd, "Login failed: too many failed attempts\n");
    return LOGIN_FAIL_IP_BANNED;
  }

  // Check password is correct and record success/failure
  if (!account_validate_password(acc, password)) {
    account_record_login_failure(acc);
    dprintf(log_fd, "Login failed: bad password for user '%s'\n", userid);
    dprintf(client_output_fd, "Login failed: incorrect password\n");
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  // Password was correct
  account_record_login_success(acc, client_ip);

  // Populate session struct
  session->account_id = acc->account_id;
  session->session_start = login_time;
  session->expiration_time = login_time + 3600; // 1 hour session (I can't find anything about session time)

  dprintf(log_fd, "Login success: user '%s'\n", userid);
  dprintf(client_output_fd, "Login successful\n");

  //Return appropriate login_result_t
  return LOGIN_SUCCESS;
}