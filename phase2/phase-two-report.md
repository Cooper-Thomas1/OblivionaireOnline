# Phase 2 Report

**Group Name**: **TOC/TOUah** (Group 33)  
**Date**: Wednesday, May 14, 2025

## Group Members

| Name             | Student Number |
|------------------|---------------|
| Cooper Thomas    | 23723986      |
| Elke Ruane       | 23748615      |
| Fin O'Loughlin   | 23616047      |
| Marc Labouchardiere | 23857377   |
| Mika Li          | 24386354      |

## GENERAL DESIGN CHOICES

### KEY DESIGN DECISIONS

Our group decided upon discussing the rubric to assume the following:

- **Parameter assumptions**  
  We assume inputs such as pointers and strings are valid and conform to the specification (e.g., null-terminated). This avoids redundant validation and aligns with separation of responsibilities in modular design. Revalidating inputs could introduce undefined behavior or reduce performance unnecessarily.

- **Account data storage**  
  `account_t` structs are allocated on the heap and manually freed, as there is no indication of persistent storage. The `db.h` header only provides function declarations, suggesting that in-memory management is expected and sufficient.

- **Logging and DB stubs**  
  Since logging and database functions are provided as stubs, our responsibility is limited to calling them correctly. We use `log_message()` to report errors, but we do not handle error recovery internally. This follows the layered approach to the *OO* system our group has decided.

- **Client abstraction**  
  We treat `client_output_fd` as an abstraction for client communication. It is assumed that file descriptors are valid, and that low-level networking tasks (like buffering and concurrency) are dealt with in higher-levels of the *OO* system.

- **Time Handling**  
  We use `time(NULL)` to obtain the current time for handling bans and expirations. This is the conventional and portable way to represent "now" in C, and no alternative timing source was specified in the rubric.

- **Thread safety handling**  
  We assume that thread safety is managed by the caller or higher-level components. Our functions do not modify shared global state, so internal thread-safety mechanisms would be unnecessary and potentially over-engineered for our low-level implementations.  
  `account_t` itself is not necessarily global or shared, but rather how instances of it are accessed (e.g., in `alternate_main.~~~~c`). Thus, our team in implementing phase 2 are not responsible for thread safety, rather the callers.

### DIFFICULTIES WE ENCOUNTERED

Our group faced the following issues when completing phase 2 on this project (and how we addressed them):

- Ambiguity around thread safety
- Choosing field lengths and NULL-terminators
- Proper use of stub functions (e.g., logging, DB)
- Balancing "reasonable assumptions" vs "project specs"
- Issues over version control robustness (i.e., pull requests reviewed by everyone doesn't really work)
- Commenting and code clarity

## FUNCTION DESIGN CHOICES

### 3.3 Account management

```c
account_t *account_create(const char *userid, const char *plaintext_password,
const char *email, const char *birthdate);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Explicit null termination** | `strncpy()` doesn't guarantee null termination if the source string exceeds buffer length. Explicit null termination corrects this. |
| **Bounded string copy using `strncpy()`** | Prevents buffer overflow by ensuring none of the values parsed to the function exceed their respective buffer length. |
| **Use `sodium_memzero()` to initialise account_t structure** | Ensures all fields are set to 0 before working with them, makes default values predictable and secure. In some cases `memset()` can be optimised out, so this is a better alternative. |
| **Validate email to ensure only printable, non-whitespace ASCII characters are used** | Prevents injection attacks, keeps data clean and avoids potential issues with handling data later. |
| **Check for valid birthdate, including leap years and future** | Improves data integrity, ensures users' birthdates are real, prevents any issues when working with dates later. |
| **Free allocated memory on failure** | Using `free(new_account);` immediately followed by `return NULL;` when validation fails prevents dangling pointers and memory leaks and ensures clean failure. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Ensuring null termination when copying** | For each value set `value[VALUE_LENGTH - 1] = '\0'` to guarantee a null terminated string. |
| **Validating Birthdate** | Used `sscanf()` for formatting and other checks to ensure the date was real including leap years. |
| **Validating Email** | Used `isprint()` and `isspace()` to ensure email consists of printable and non-whitespace ASCII characters. |

```c
void account_free(account_t *acc);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Check for null inputs** | `if(acc == NULL)` protects against dereferencing a null pointer which would cause undefined behaviour. |
| **Use `memset()` to zero all values before freeing** | Ensures sensitive account data has no way of being accessed after `free(acc)`. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Sensitive data may still be accessible** | Using `memset()` to overwrite the memory reduces the chance that sensitive data still remains in memory after deallocation. |

```c
void account_set_email(account_t *acc, const char *new_email);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Trim trailing newline** | To avoid storing unwanted newline characters that could come from user input (e.g., from `fgets`). |
| **Bounded string copy using `strncpy()`** | Prevents buffer overflow by ensuring that no more than `EMAIL_LENGTH - 1` characters are copied. |
| **Explicit null termination** | Guarantees a null-terminated string even when `strncpy` doesn't automatically do so. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Trailing newline character** | Stripped the newline by checking `new_email[len - 1] == '\n'` and reducing the length accordingly. |
| **Ensuring null-termination when copying** | Explicitly set `acc->email[len] = '\0'` to prevent issues with un-terminated strings. |

```c
void account_set_unban_time(account_t *acc, time_t t);
void account_set_expiration_time(account_t *acc, time_t t);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Check if `t >= 0`** | To prevent assigning invalid negative values to `unban_time` or `expiration_time`, ensuring valid data. |
| **No assignment for negative values** | Fosters data integrity by rejecting unreasonable values. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Handling negative times** | Added a check for `t >= 0` to avoid unintentional assignment of invalid time values. |

```c
bool account_is_banned(const account_t *acc);
bool account_is_expired(const account_t *acc);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Check `unban_time > 0` or `expiration_time > 0` before comparison** | Only evaluate when these fields have been explicitly set to non-zero values, preventing false positives. |
| **Use of `time(NULL)`** | Retrieves the current time in a portable, reliable way to compare against the account's ban or expiration time. |
| **Return `true` if conditions match** | `account_is_banned()` returns `true` when the account is still banned (current time before `unban_time`), and `account_is_expired()` when the account has expired (current time after `expiration_time`). |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Comparing against current time correctly** | Used `time(NULL)` to get the current system time and compare it against `unban_time` or `expiration_time`. |

```c
void account_record_login_success(account_t *acc, ip4_addr_t ip);
void account_record_login_failure(account_t *acc);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Reset `login_fail_count` or `login_count` to 0** | A successful login (failed login) resets the failure count (the success count), as specified in the spec. |
| **Check for `UINT_MAX` before increment** | Prevents unsigned integer overflow. |
| **Record `last_login_time` using `time(NULL)`** | Captures the current login time in a suitable way. |
| **Store IP address in `last_ip` field** | Keeps track of the IP for displaying user information. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Potential for `login_count` or `login_fail_count` overflow** | Added a conditional check before incrementing. |

```c
bool account_print_summary(const account_t *acct, int fd);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Use `memcpy` with explicit null termination on strings** | Use memcpy with explicit null termination on strings. |
| **Use `localtime_r` and `strftime`** | Produces safe and human-readable time output. |
| **Use `inet_ntop` for IP formatting** | Converts raw IP to readable form. |
| **Return false if `dprintf` fails** | Ensures caller is aware of I/O issues. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Non-null-terminated userid/email risk** | Used safe buffers with explicit null-termination. |
| **Formatting IP and time output** | Used standard C functions (`inet_ntop`, `strftime`). |

### 3.4 Password Handling

```c
bool account_validate_password(const account_t *acc,
const char *plaintext_password
);
```

| Design Decision | Justification |
| --------------- | ------------- |
| -               | -            |
| -               | -            |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      | -      |
| -                      | -      |

```c
bool account_update_password(account_t *acc,
const char *new_plaintext_password
);
```

| Design Decision | Justification |
| --------------- | ------------- |
| -               | -            |
| -               | -            |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      | -      |
| -                      | -      |

### 3.5 Login Handling

```c
login_result_t handle_login(const char *username, const char *password,
ip4_addr_t client_ip, time_t login_time,
int client_output_fd,
login_session_data_t *session);
```

| Design Decision | Justification |
| --------------- | ------------- |
| -               | -            |
| -               | -            |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| -                      | -      |
| -                      | -      |
