#include "login.h"
#include "account.h"
#include "logging.h"
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>

// Sends a formatted message to the client via the provided file descriptor.
// Assumes fixed message templates and no dynamic format input from user.
// Buffer size is limited to longest known message in use.
static void client_output_message(int fd, const char *fmt, ...) {
    char buf[50];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // Avoid undefined behavior from vsnprintf failure
    if (len > 0 && len < sizeof(buf)) {
        write(fd, buf, len);
    }
}

login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd, int log_fd,
                            login_session_data_t *session) 
{
    account_t acc;

    // Attempt to retrieve account data for the given user ID.
    if (!account_lookup_by_userid(userid, &acc)) {
        log_message(LOG_WARN, "Login failed: user '%s' not found", userid);
        client_output_message(client_output_fd, "Login failed: user not found\n");
        return LOGIN_FAIL_USER_NOT_FOUND;
    }

    // Check if account is expired.
    if (account_is_expired(&acc)) {
        log_message(LOG_WARN, "Login failed: account '%s' expired", userid);
        client_output_message(client_output_fd, "Login failed: account expired\n");
        return LOGIN_FAIL_ACCOUNT_EXPIRED;
    }

    // Check if account is currently banned.
    if (account_is_banned(&acc)) {
        log_message(LOG_WARN, "Login failed: account '%s' is banned", userid);
        client_output_message(client_output_fd, "Login failed: account is banned\n");
        return LOGIN_FAIL_ACCOUNT_BANNED;
    }

    // Enforce temporary IP ban after too many failed login attempts.
    if (acc.login_fail_count >= 10) {
        log_message(LOG_WARN, "Login failed: too many failed login attempts for user '%s'", userid);
        client_output_message(client_output_fd, "Login failed: too many failed login attempts\n");
        return LOGIN_FAIL_IP_BANNED;
    }

    // Validate the provided password.
    if (!account_validate_password(&acc, password)) {
        account_record_login_failure(&acc);
        log_message(LOG_INFO, "Login failed: incorrect password for user '%s'", userid);
        client_output_message(client_output_fd, "Login failed: incorrect password\n");
        return LOGIN_FAIL_BAD_PASSWORD;
    }

    // Successful login: record and populate session information.
    account_record_login_success(&acc, client_ip);

    session->account_id = acc.account_id;
    session->session_start = login_time;
    session->expiration_time = 0;  // Infinite session duration

    log_message(LOG_INFO, "Login success: user '%s' authenticated from IP %u", userid, client_ip);
    client_output_message(client_output_fd, "Login successful!\n");

    return LOGIN_SUCCESS;
}
