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

We will meet weekly to discuss weekly updates, progress reports and adjusting our high-level approaches to the project in face-to-face meetings at UWA on Wednesday 
mornings. As well as our weekly status updates, we will implement ad hoc emergency meetings through MS Teams as required when there are critical bugs and fixes required. 
Our preferred communication tool is MS Teams where will discuss the bulk of the project.

**UPDATE**: Our team will hold `weekly face-to-face` meetings at UWA on Wednesday mornings. These will allow us to provide weekly status updates, issues, challenges, etc. Our preferred communication tool, as well as any ad hoc emergency meetings will be hosted via `Microsoft Teams`, where requiref for critical bugs/fixed required. 


> Define how responsibilities will be allocated in phase 2. Who will be responsible for which tasks?

Tasks will be assigned based on each member's strengths and preferences to encourage motivation and to completion. For examples:

- **Cooper** - Team leader. Is in charge of submissions, coordination of group meetings, keeping track of the development of sections of work.
- **Elke** - In charge of `Player authentication`
- **Fin** - In charge `Session management`
- **Marc** - In charge of `Role-based access control`
- **Mika** - In charge `Admin and operations access`

As a group we will plan how to implement each task and comprehensively discuss the requirements before we start writing any code, speicifically following an Agile framework. As some sections are dependent on the ones before them to be completed, we will coordinate between group members on how these requirements will be facilitated and jump between tasks/features as necessary - particularly the team leader.


> How will the group ensure accountability and track progress?

We will ensure accountability and progress by doing weekly status reports in our team meetings where each member will give updates on what they’ve been working on in the last week as well as any recurring problems that they may need extra support on. Furthermore, by utilising GitHub’s version control we can track all changes with a comprehensive history of what changes were made, when they occurred and who implemented them.


**UPDATE** Each week, team members will be accountable to doing `weekly status reports` in our team meetings. This is a space where each member can give updates on what they have been working on in the last week, as well as any problems encountered. 

We will also be `GitHub` for version control, where we can track all changes with a comprehensive history of what changes were made, when they occurred, and who implemented them.

---

## 2. Version Control Strategy

> Specify where the project’s source code will be hosted (e.g., GitHub, GitLab, Bitbucket). How will you handle merging members’ contributions?

Our source code will be written on `GitHub`, and we will handle merges by making sure each change is done using a pull request which guarantees all changes are approved in a code review by another group member before any changes to our code base are pushed. 


> If you’re familiar with version control branching strategies, will you adopt any particular strategy or workflow? (e.g., feature branches, main/dev workflow). 

We will adopt a `main/dev` workflow, with feature specific branching within each dev branch as necessary.

- The `main` branch will contain production-ready code.
- The `dev` branch will be the integration branch where feature branches are merged after testing
- Each group member will create feature-specific branches based on assigned components (e.g. `feature/operation-access`). This structure helps reduce merge conflicts and allows us to work on the project simultaneously.

We chose to use feature branching within dev branches as we believe it aligns better with the requirements of our clients needs and means that devs in the team can jump between features as necessary without interupting the workflowm of the project.


> Identify any version control policies (e.g., commit message conventions, review/approval process before merging).

All changes will undergo a peer review before merging. This can be done via a `pull request` that must be approved by at least two other group members before merging into `dev` or `main`. 

We will follow consistent commit message convention:
- What was changed
- Why it was changed
- Any remaining issues/future improvements


---

## 3. Development Tools

>List the common tools the group will use for implementation:
Code editor or IDE (e.g., VS Code, JetBrains, Vim); Any additional tools for collaboration or efficiency (e.g., linters, debugging tools, CI/CD services). Explain why you made these choices.

The standardised code editor where we will produce our C code within is VSCode as well as making use of several debuggers/linters including the gcc GNU debugger 
specifically the gcc compiler configuration below for compiling our code in the testing phase 
```
gcc -std=c89 -pedantic -Wall \
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

*this was sourced from https://stackoverflow.com/questions/154630/recommended-gcc-warning-options-for-c as recommended in Lab 6*

We chose to use the gcc debugger as, in the lectures and labs, it has proved to be an effective and trusted debugging tool, which we all have familiarity with and confidence in.


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

Potential risks surrounding resourcing will certainly play a role in our project and thus must be strongly considered in 
our scope and project requirements. These resource risks include group member illnesses, service outages and …. 
Furthermore, an unlikely but still security critical element is that other teams do not gain access to our plans and 
particularly our code repositories, to avoid this we need to ensure that our GitHub repo remains private, and members do 
not give access or share details of the project to external stakeholders. Technical risks of the project include missing 
key elements of the privilege separation or privilege elevation requirements. 

> Describe how code quality will be maintained:
– Will the group follow a specific coding standard?
– Will peer reviews, automated testing, or static analysis tools be used?

Code quality will be maintained by following the CERT C Secure Coding Standard, which provides guidelines for secure and reliable coding practices in C particularly involving what to do in the case of integer/buffer overflow and uninitialized variables. We will also aim to align our 
style with Google’s C Style Guide. Peer reviews will be done manually from group members whenever changes are made to our 
code base using GitHub’s pull request capability. We will also use automated testing methods by creating unit tests using Unity, a popular and lightweight framework for C development. Furthermore, Clangs static analyser will be implemented in our code as well.

---

## 6. Group Name
  **Group Name**: Protectors of Privileges


