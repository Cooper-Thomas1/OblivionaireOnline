# CITS3007 Group Project – Phase 1 Report 
**Group Name**: *Protectors of Privileges*\
**Group Number**: *33*\
**Date**: 16 Apr 2025

---

## Group Members

| Name | Student Number |
|--------------------|----------------|
| Cooper Thomas | 23723986 |
| Elke Ruane | 23748615 |
| Fin O'Loughlin | 23616047 |
| Marc Labouchardiere | 23857377 |
| Mika Li | 24386354 |

---

## 1. Team Communication & Responsibilities

> Describe how the group will communicate throughout the project: Frequency of meetings (e.g., weekly; fortnightly; as needed); Meeting format (e.g., face-to-face; online via video calls or chat platforms); Preferred communication tools (e.g., Discord, Slack, MS Teams, email)

Our team will hold `weekly face-to-face` meetings at UWA on Wednesday mornings. These will allow us to provide weekly status updates, issues, challenges, etc. As well as our weekly status updates, we will implement ad hoc emergency meetings through MS Teams as required when there are critical bugs and fixes required. Our preferred communication tool will be `Microsoft Teams`, where we will discuss the bulk of the project.


> Define how responsibilities will be allocated in phase 2. Who will be responsible for which tasks?

Tasks will be assigned based on each member's strengths and preferences to encourage motivation and completion. These sections will be divided based on the project description, which is divided into 4 sections. For example:

- **Cooper** - Team leader. In charge of submissions, coordination of group meetings, keeping track of the development of sections of work. 
- **Elke** - In charge of `Player authentication`
- **Fin** - In charge of `Session management`
- **Marc** - In charge of `Role-based access control`
- **Mika** - In charge of `Admin and operations access`

As a group we will plan how to implement each task and comprehensively discuss the requirements before we start writing any code, specifically following an Agile framework. As some sections are dependent on the ones before them to be completed, we will coordinate between group members on how these requirements will be facilitated and jump between tasks/features as necessary - particularly the team leader.


> How will the group ensure accountability and track progress?

Each week, team members will be accountable to doing *weekly status reports* in our team meetings. This is a space where each member can give updates on what they have been working on in the last week, as well as any problems encountered. These features and changes will be logged via the `Issues` tabs, where any suggestions/improvements to the code can be contributed by group members.

---

## 2. Version Control Strategy

> Specify where the project’s source code will be hosted (e.g., GitHub, GitLab, Bitbucket). How will you handle merging members’ contributions?

We will use `GitHub` for version control, where we can track all changes with a comprehensive history of what changes were made, when they occurred, and who implemented them. We will handle merges by making sure each change is done via a `pull request`, which provides the opportunity for new feature's code to be reviewed. We will be aiming to have `pull requests` reviewed by two other group member before any changes to our code base are pushed. `Pull request` provide a structured way to review code, suggest changes, and to discuss code, ensuring code quality, and provides a means of collaboration between group members.


> If you’re familiar with version control branching strategies, will you adopt any particular strategy or workflow? (e.g., feature branches, main/dev workflow). 

We will adopt a `main/dev` workflow, with feature specific branching within each dev branch as necessary.

- The `main` branch will contain production-ready code.
- The `dev` branch will be the integration branch where feature branches are merged after testing
- Each group member will create feature-specific branches based on assigned components (e.g. `feature/operation-access`). This structure helps reduce merge conflicts and allows us to work on the project simultaneously.

We chose *feature branching* within the `dev` branch as we believe it aligns better with the requirements of our clients needs, and means that developerss in the team can jump between features as necessary without interupting the workflow of the project.


> Identify any version control policies (e.g., commit message conventions, review/approval process before merging).

All changes will undergo a peer review before merging. This can be done via a `pull request` that must be approved by at least two other group members before merging into `dev` or `main`. 

We will also follow consistent commit message convention:
- What was changed
- Why it was changed
- Any remaining issues/future improvements

Good commit messages are important for maintaining a clear and understandable project history, and will allow us (or other developers) to quickly see what changes were made and why. 

---

## 3. Development Tools

>List the common tools the group will use for implementation:
Code editor or IDE (e.g., VS Code, JetBrains, Vim); Any additional tools for collaboration or efficiency (e.g., linters, debugging tools, CI/CD services). Explain why you made these choices.

Visual Studio Code (`VSCode`) will be the standardised code editor where we will create our `C` programs. We selected `VSCode` due to its lightweight nature, cross-platform compatibility, and extensive extension ecosystem that supports C development, including syntax highlighting (via `IntelliSense`), integrated terminal, in-built `Git` integration, and debugging capabilities.

For compiling and debugging, we will use the GCC compiler (for type errors) along with the `GDB debugger` (for logic errors). We have chosen to adopt a strict compiler configuration (see below) during the development and testing phases to enforce secure coding practices and to catch common sources of bugs early. This configuration enables a comprehensive set of warning flags and debugging options that align with secure `C` programming principles taught in the lectures and labs.

```Makefile
gcc -std=c11 -pedantic -Wall \
	     -Wno-missing-braces -Wextra -Wno-missing-field-initializers \
	     -Wformat=2 -Wswitch-default -Wswitch-enum -Wcast-align \
	     -Wpointer-arith -Wbad-function-cast -Wstrict-overflow=5 \
	     -Wstrict-prototypes -Winline -Wundef -Wnested-externs \
	     -Wcast-qual -Wshadow -Wunreachable-code -Wlogical-op \
	     -Wfloat-equal -Wstrict-aliasing=2 -Wredundant-decls \
	     -Wold-style-definition -Werror \
	     -ggdb3 \
	     -O0 \
	     -fno-omit-frame-pointer -ffloat-store \
	     -fno-common -fstrict-aliasing \
	     -lm
```

*This was sourced from https://stackoverflow.com/questions/154630/recommended-gcc-warning-options-for-c as recommended in Lab 6*

Additionally, we will use GDB (GNU Debugger) for runtime debugging. GDB has been consistently used in CITS3007 labs, and all team members are familiar with its workflow. Its integration with VS Code allows for seamless breakpoints, step-through debugging, and variable inspection—crucial for diagnosing issues in low-level C code.

We are also exploring the use of clang-tidy / cppcheck for static code analysis as our research into them suggests they are a highly useful tool for ensuring secure and safe code.


---

## 4. Key Secure Coding Practices for Phase 2

>Identify three security-related tools or practices covered in the unit that will be most
critical during phase 2. For each, explain: why it is relevant to the project; how it will be applied during development; and how the group will ensure it is effectively used.

The **gcc debugger** will be relevant to the project as it is essential to have a comprehensive debugging tool to catch errors and potential mistakes which ‘fall through the cracks’ of standard compiling. It will be applied within our development process every time we compile any C code, and we will guarantee its effective use by ensuring all members use the same debugger and compiling specifications.

The security practice of ensuring **secure over efficient code** is also highly relevant to our project and its associated requirements as it dictates our development
philosophy and what is prioritized within the process. It will be applied in our development whenever there is an implementation or high-level decision which involves
choosing whether to prioritize secure, readable code or efficient, fancy code. The group will ensure this secure coding philosophy is effectively implemented by
conferring with each other before making such decisions and by having secure, understandable code always at the forefront of our processes.

The use of **static code analysis tools** like splint will be relevant to our project as they help detect vulnerabilities and bad practices before runtime. It will be
applied regularly during development to review code for security issues. The group will ensure effective use by making splint checks part of our coding workflow and
reviewing any flagged warnings together.

---

## 5. Risk Management & Quality Assurance

> Outline potential risks to the project and how they will be mitigated. (You may wish to think about resourcing risks – e.g. member illness, service outage – as well as technical and operational risks.)

1. Group Member Illnesses/ Service Outages  
   An important risk to the project are resourcing risks where we may have interuptions to our work or an increased workload due to member unavailability. To mitigate this, we will ensure our code is readable and every
   group member understands all aspects of the project so there is no tech debt.

2. Authentication Logic Errors  
   A critical risk is the incorrect implementation of authentication or session handling which could lead to unauthorized access. To mitigate this, we will design the login flow early and review all authentication related
   code during peer reviews in our Wednesday meetings.

3. Insecure Password Handling  
   Storing or transmitting passwords insecurely is a serious security risk. To mitigate this, we will use secure hashing such as SHA256 with salt and ensure sensitive data is encrypted.

4. Unvalidated Input  
   Failing to validate user input can lead to injection attacks. To mitigate this, we will sanitise all inputs and avoid unsafe C functions like gets(), instead using functions like fgets().

5. Poor Privilege Handling  
    Missing edge cases in privilege elevation could expose admin functions to regular users. To mitigate this, we will implement test cases covering access control logic.

6. Low C Security Familiarity  
    Not all team members may be comfortable with secure C programming practices. To mitigate this, we will share resources and get more experienced members to help them out when needed.

7. Tool Conflicts and Merge Errors  
    Version control conflicts or tool inconsistencies could disrupt progress. To mitigate this, we'll adopt a feature-branch strategy, standardise our build environment using a shared Makefile, and conduct merges through
    pull requests.

> Describe how code quality will be maintained:
– Will the group follow a specific coding standard?
– Will peer reviews, automated testing, or static analysis tools be used?

Code quality will be maintained by following the CERT C Secure Coding Standard, which provides guidelines for secure and reliable coding practices in C particularly involving what to do in the case of integer/buffer overflow and uninitialized variables. We will also aim to align our style with Google’s C Style Guide. Peer reviews will be done manually from group members whenever changes are made to our code base using GitHub’s pull request capability. We will also use automated testing methods by creating unit tests using Unity, a popular and lightweight framework for C development. Furthermore, Clangs static analyser will be implemented in our code as well.

---

## 6. Group Name
  **Group Name**: Protectors of Privileges


