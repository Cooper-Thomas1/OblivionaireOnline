#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h> // for dprintf
#include "login.h"
#include "banned.h"

int main(void) {
    login_session_data_t session;
    ip4_addr_t dummy_ip = 0x7F000001; // 127.0.0.1
    time_t now = time(NULL);

    // Test: user not found
    dprintf(1, "Test 1: User not found\n");
    int res = handle_login("alice", "password", dummy_ip, now, 1, &session);
    dprintf(1, "Result: %d\n\n", res);

    // Test: user found (bob), wrong password
    dprintf(1, "Test 2: Bob, wrong password\n");
    res = handle_login("bob", "wrongpassword", dummy_ip, now, 1, &session);
    dprintf(1, "Result: %d\n\n", res);

    // Test: user found (bob), correct password (if stub accepts any)
    dprintf(1, "Test 3: Bob, correct password\n");
    res = handle_login("bob", "password", dummy_ip, now, 1, &session);
    dprintf(1, "Result: %d\n\n", res);

    return 0;
}