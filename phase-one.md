**Team Communication & Responsibilities**

  We will meet weekly to discuss weekly updates, progress reports and adjusting our high-level approaches to the project in face-to-face meetings at UWA on Wednesday 
  mornings. As well as our weekly status updates, we will implement ad hoc emergency meetings through MS Teams as required when there are critical bugs and fixes required. 
  Our preferred communication tool is MS Teams where will discuss the bulk of the project.
  We will fairly distribute tasks by aiming to assign them according to each members strengths and preferences. Specifically, Cooper will do …. We will ensure accountability 
  and progress by ding weekly status reports in our team meetings where each member will give updates on what they’ve been working on in the last week as well as any 
  recurring problems that they may need extra support on. Furthermore, by utilising GitHub’s version control we can track all changes with a comprehensive history of what 
  changes were made, when they occurred and who implemented them.

**Version Control Strategy** 

  Our source code will be written in GitHub, and we will handle merges by ensuring all changes are approved in a code review by another group member before any changes to 
  our code base are pushed. Each member will be assigned a particular section to work on and will create their own branch to avoid clashes thus increasing efficiency by 
  eliminating unnecessary overlapping work. Specifically, our version control implementation strategy will be a main/dev workflow with feature specific branching within each 
  dev branch as necessary. To maintain uniformity in our project we will ensure that all commit messages specify three things; what was the change made, why was the change 
  made and any potential improvements/problems still to be done. Furthermore, each push should be reviewed by at least one other group member before being pushed to main.

**Development Tools** 

  The standardised code editor where we will produce our C code within is VSCode as well as making use of several debuggers/linters including the gcc GNU debugger 
  specifically gcc -pedantic -Wall -Wextra -Wconversion -Wshadow my_program.c -o my_program when compiling our C code. We chose to use the gcc debugger as, in the lectures 
  and labs, it has proved to be an effective and trusted debugging tool, which we all have familiarity with and confidence in.

**Key Secure Coding Practices for Phase 2** 

  1.	The gcc debugger will be relevant to the project as it is essential to have a comprehensive debugging tool to catch errors and potential mistakes which ‘fall through
      the cracks’ of standard compiling. It will be applied within our development process every time we compile any C code, and we will guarantee its effective use by
    	ensuring all members use the same debugger and compiling specifications.
  3.	The security practice of ensuring secure over efficient code is also highly relevant to our project and its associated requirements as it dictates our development
      philosophy and what is prioritized within the process. It will be applied in our development whenever there is an implementation or high-level decision which involves
    	choosing whether to prioritize secure, readable code or efficient, fancy code. The group will ensure this secure coding philosophy is effectively implemented by
    	conferring with each other before making such decisions and by having secure, understandable code always at the forefront of our processes.
  5.	The use of static code analysis tools like splint will be relevant to our project as they help detect vulnerabilities and bad practices before runtime. It will be
      applied regularly during development to review code for security issues. The group will ensure effective use by making splint checks part of our coding workflow and
    	reviewing any flagged warnings together.

**Risk Management & Quality Assurance** 

  ...

**Group Name** 

  Protectors of Privileges


