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
  We assume inputs such as pointers and strings are valid and conform to the specification (e.g., not null-terminated). This avoids redundant validation and aligns with separation of responsibilities in modular design. Revalidating inputs could introduce undefined behavior or reduce performance unnecessarily.

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
  `account_t` itself is not necessarily global or shared, but rather how instances of it are accessed (e.g., in `alternate_main.c`). Thus, our team in implementing phase 2 are not responsible for thread safety, rather the callers.

### DIFFICULTIES WE ENCOUNTERED

Our group faced the following issues when completing phase 2 on this project (and how we addressed them):

- Ambiguity around thread safety
- Ambiguity in the project specs
- Choosing field lengths and NULL-terminators
- Proper use of stub functions (e.g., logging, DB)
- Balancing "reasonable assumptions" vs "project specs"
- Issues over version control robustness (i.e., pull requests reviewed by everyone doesn't really work)
- Commenting and code clarity
- Not using banned functions

### FUNCTION SPECIFIC DESIGN DECISIONS/DIFFICULTIES

#### `account.c` FUNCTIONS

##### HELPER FUNCTIONS

```c
bool validate_email(const char *email, size_t *out_len);
```

- On bigger than `EMAIL_LENGTH` strings, then we assume that the caller did not intend that (i.e. pass an invalid length email). Thus we throw a warning and truncate to `EMAIL_LENGTH` the email into `account_t.email`, and carry on with the code.
- On success copy the strlen of the amount of bytes to copy (up to `EMAIL_LENGTH`). This ensures the correct amount of bytes are copied in subsequent `memcpy` calls.
- Issues with what we should constitute as a valid email. Does it need a "@" symbol? does it need characters on either side of the "@" symbol? Is the empty string valid? In the end, we decided to follow the project spec strictly, and only permit ASCII printable characters with no spaces. Thus the empty string is valid.

```c
bool validate_birthdate(const char *bday, size_t *out_len);
```

- Assumes that the caller can reasonably pass the string `0000-00-00` as a default value, and this is explicitly permitted. As given in `account.h`.
- Assumes all dates are permitted. This is strictly following the project specs.
- Assumes the `time.h` library safely validates dates.
- Had issues with the formatting of the birthdate string, as originally we were trying to store the NULL-terminator which would overwrite the 10th byte of the birthdate (which was incorrect). In the end, we decided to not store the NULL-terminator in the `account_t->birthdate` field to store the correct amount of bytes.

```c
bool hash_password(const char *pw, char *out_hash, size_t out_hash_len);
```

- Assumes that the `pw` string is small enough to be put into the `libsodium crypto_pwhash_str_alg()` call. Have stress tested and that it appears the arbitrary limits on C string sizes limit the strings first.
- Issues with selecting a secure and easy to use crypto library, settled for `libsodium` with safe default values that seem to fit salt + hash into the `HASH_LENGTH` as defined in `account.h`, so stuck with it.

```c
int safe_memcpy(char *dest, const char *src, size_t max_len);
```

- Designed to check for overlapping `src` and `dest` buffers, before calling `memcpy`. Prevents undefined behaviour for overlap in `memcpy` (e.g. partial copying)
- Assumes `dest` and `src` are valid, non-NULL pointers
- We originally implemented a `safe_strncpy(...)`, which would copy params as strings into the account struct fields, but this became deprecated when we realised that storing the NULL-terminator was not allowing us to store the full amount of memory for a field, as the account struct is not forgiving (i.e. not possible to) in allocating more space for the NULL-terminator. 

##### ACTUAL FUNCTIONS

```c
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      );
```

- Assume that `acc->userid` should fit into the size `USER_ID_LENGTH`, or else the caller will get a warning via system log, and the `userid` value will be truncated. This seems reasonable and is documented to the caller.
- Uses helper functions as described above
- Explicitly sets all other values in the `account_t` struct to 0 for clarity and readability.
- Had issues with whether we needed helper functions or not. What they would return? ended up creating helper functions that return true on valid, and false on invalid fields. This also follows DRY, where these validating functions are reused throughout our code, especially when updating an account field.

```c
void account_free(account_t *acc);
```

- Assumes a user would not try free a NULL account pointer, so will warn in a system log.
- Sets all data in `account_t` to 0 using a `libsodium` provided function `sodium_memzero()` that is guaranteed to not be optimised away. This is done to prevent sensitive user info left in the heap (for unauthorised eyes to see...)
- Issue with initial implementation using `memcpy()`

```c
bool account_validate_password(const account_t *acc, const char *plaintext_password);
bool account_update_password(account_t *acc, const char *new_plaintext_password);
```

- Passes off responsibility to `libsodium` with a password comparator `crypto_pwhash_str_verify`. Assumes the `plaintext_password` is small enough to work with the library...
- When updating the password, we remove the old one using `sodium_memzero` explicitly just in case if the old password hash may linger (even just partially) in unused memory in the `account_t` field. Securely erases.

```c
void account_record_login_success(account_t *acc, ip4_addr_t ip);
void account_record_login_failure(account_t *acc);
```

- If the `acc->login_count` is at `UINT_MAX`, then we don't increment as this would wrap around to zero (unsigned int behaviour). We don't log a warning as if a malicious user was to try DoS by spamming the login, we would not want our system logs to be spammed with *login count at UINT_MAX* as it would be a nightmare to trawl...
- Accesses system clock `time(NULL)` to store "now", not so worried about its implementation.
- Initial issues with unsigned integer overflows, thus adding `UINT_MAX` check.

```c
bool account_is_banned(const account_t *acc);
bool account_is_expired(const account_t *acc);
```

- Was trivial to implement.
- No issues

```c
void account_set_unban_time(account_t *acc, time_t t);
void account_set_expiration_time(account_t *acc, time_t t);
```

- Assumes the caller understands what the `t` value they are passing is valid and works with the high-levels of the *OO* system. E.g. our code does not check for `t < 0` as the caller may have a specific meaning for negative unban times, and our group has prioritised following the project spec.
- Issues with *what constitutes as a valid `t` value*, decided the project spec does not specify, thus better not to make assumptions...

```c
void account_set_email(account_t *acc, const char *new_email);
```

- Wrapper around the `bool validate_email(...)`, DRY. Reuse of code used in `account_create()`.
- Nothing much to add, see `account_create`

```c
bool account_print_summary(const account_t *acct, int fd);
```

- Assuming that all the data in the `account_t` are not properly NULL-terminated, so must be manually added. This allows us to properly store the full value of bytes as defined in `account.h` without having to worry about storing the NULL-terminator. These "pseudo-strings" are thus converted into strings at the start of this function.
- `time` and `arpa/inet` libraries are concerned with safely converting our `account_t` fields into printable formats. Using safe library calls.
- Uses an out buffer `outbuf` with a max length of 512 to write the message to be written into. This size is larger than the largest possible message (with maxed out fields) can be to avoid truncation.
- No sensitive data is displayed, as if higher levels of the *OO* system can use this function, that sensitive data like passwords hashes and the like are not accessible (and thus not displayed).

#### `login.c` FUNCTIONS

##### HELPER FUNCTIONS

##### ACTUAL FUNCTIONS

## FUNCTION DESIGN CHOICES

### 3.3 Account management

```c
account_t *account_create(const char *userid, const char *plaintext_password,
const char *email, const char *birthdate);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Creating helper functions to validate account parameters, `validate_email()`, `validate_birthdate()`, `hash_password()`** | Improving readability and modularisation by creating helper functions to perform tasks needed to create the account. Allows for these functions to be called elsewhere if needed. *Not sure if i should go into detail about what the functions do?* |
| **Bounded string copy using `safe_memcpy()`** | Ensures memory safety by checking for buffer overflows and overlapping memory regions before copying data, helping to prevent undefined behavior and memory corruption. |
| **Use `sodium_memzero()` to intialise account_t structure** | Ensures all fields are set to 0 before working with them, makes default values predictable and secure. In some cases `memset()` can be optimised out, so this a better alternative. |
| **Use `strnlen()` before copying `userid`** | This prevents reading beyond the limits of the buffer. |
| **Validate email to ensure only printable, non whitespace ASCII characters are used** | Prevents injection attacks, keeps data clean and avoids potential issues with handling data later. |
| **Explicitly set account_t values to zero. e.g `new_account->account_id = 0;`** | Explicitly setting the values to 0 after using `sodium_memzero()` is to avoid any potential errors and it helps to improve readability. |
| **Free allocated memory on failure** | Using `free(new_account);` immediately followed by `return NULL;` when validation fails prevents dangling pointers and memory leaks and ensures clean failure. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Ensuring safe copying of inputs to avoid overflow issues** | Creating custom function `safe_memcpy()` to avoid any possible security issues when copying a user input. |
| **Validating Birthdate** | Accounting for future dates using `time.h` library. Using potentially unsafe function `sscanf()` to read the birthdate is not an issue in our case as we know the value is a valid null terminated input |
| **Validating Email** | Used `isprint()` and `isspace()` to ensure email consists of printable and non whitespace ASCII characters. |
| **Hashing Password**| Used the libsodium Argon2id algorithm to ensure effective hashing of the plaintext password. |
```
void account_free(account_t *acc);
```

| Design Decision | Justification |
| --------------- | ------------- |
| **Check for null inputs** | `if(acc == NULL)` protects against dereferencing a null pointer which would cause undefined behaviour. |
| **Use `sodium_memzero()` to zero all values before freeing** | Ensures sensitive account data has no way of being accessed after `free(acc)`. |

| Difficulty Encountered | Remedy |
| ---------------------- | ------ |
| **Sensitive data may still be accessible** | Using `_sodium_memzero()` to overwrite the memory reduces the chance that sensitive data still remains in memory after deallocation. |
```
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
