## Phase 2 Report
### 3.3 Account management
```
account_t *account_create(const char *userid, const char *plaintext_password,
const char *email, const char *birthdate);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        | 
```
void account_free(account_t *acc);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
```
void account_set_email(account_t *acc, const char *new_email);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
```
void account_set_unban_time(account_t *acc, time_t t);
void account_set_expiration_time(account_t *acc, time_t t);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
```
bool account_is_banned(const account_t *acc);
bool account_is_expired(const account_t *acc);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
```
void account_record_login_success(account_t *acc, ip4_addr_t ip);
void account_record_login_failure(account_t *acc);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
```
bool account_print_summary(const account_t *acct, int fd);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
### 3.4 Password Handling
```
bool account_validate_password(const account_t *acc,
const char *plaintext_password
);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
```
bool account_update_password(account_t *acc,
const char *new_plaintext_password
);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
### 3.5 Login Handling
```
login_result_t handle_login(const char *username, const char *password,
ip4_addr_t client_ip, time_t login_time,
int client_output_fd,
login_session_data_t *session);
```
| Design Decision | Justification |
| --------------- | ------------- |
| -               |               |
| -               |               |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      |        |
| -                      |        |
