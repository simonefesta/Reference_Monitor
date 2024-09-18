# 🖥️ The Reference Monitor

**Author**: Simone Festa, University of Rome, Tor Vergata  
**Subject**: Advanced Operative Systems, y. 2023/2024  
**Developed on**: Kernel 5.15.0-117-generic

## Specifications 📜

For detailed project specifications, refer to the [Project Specification Document](https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html).

## Introduction

The aim of this project is to develop a Reference Monitor, a module that supervises the execution, based on domains. In particular, there are 4 operative modes:

- **ON**: The reference monitor is watching what is on the blacklist, but this can't be modified.
- **REC_ON**: The reference monitor is watching what is on the blacklist, and this can be modified.
- **OFF**: The reference monitor isn't watching what is on the blacklist, and this can't be modified.
- **REC_OFF**: The reference monitor isn't watching what is on the blacklist, and this can be modified.

When the reference monitor is **ON**/**REC_ON**, and a user tries to open/remove/edit a file or folder in the blacklist, this illegal action will be marked on a single-fs file, which is persistent. Information in the file will include:

- The process TGID
- The thread ID
- The user-id
- The effective user-id
- The program path-name that is currently attempting the open
- A cryptographic hash of the program file content

## USAGE 🔬
To clone the repository to your local machine:

```shell
git clone https://github.com/simonefesta/Reference_Monitor.git
cd Reference_Monitor
```
After this, we can run `sudo ./start.sh` in the main directory. This action will install the reference monitor module and the single-fs file system. To shut down the reference monitor module and the single-fs file system, we can run `sudo ./stop.sh`. If we want to remove them separately, there are ad-hoc makefiles to perform this operation.

In the middle, we can interact with the module through two ways:
- **tests**
- **user.c**


### Tests 🔍

Tests provide a simple way to understand how the project works. There are three tests in the folder `tests`.

**NB**: All the tests run assuming that the password is the default one, which is "`default`".

- **append_file_test**: In this folder, there is a file named `append_file_test.c` and a folder named `directory` which includes a file.
  The reference monitor is initially set to **REC_ON**, and the file is protected. An attempt to *write* to the file will be made first, which should fail, resulting in a log entry in `the-file`. Subsequently, the reference monitor is set to **OFF**, and a new *write* attempt will succeed, modifying the file.
We can run this test with: `sudo ./run.sh`.

- **dir_test**: In this folder, there is a `directory`, which includes the folder `trytoremove`. Run `sudo ./lock_dir.sh`, and `directory` will be black-listed, so any attempts to create (e.g: commands `touch` or `mkdir`) or remove (e.g: `rmdir`) inside will be blocked and logged.
When we finish the test, we can run `sudo ./unlock_dir.sh` to remove the protection.

- **unlinkat_test**: In this folder, there is an empty `directory`. By running `sudo ./run.sh`, this directory will be added to the blacklist. An attempt to remove this folder using `unlinkat` will be made.
This attempt should fail, the folder will still be present, and a log entry will be recorded in `the-file`.

## User 🧑‍💻

Running: 
```shell
gcc -o user user.c
sudo ./user
```
allows us to interact with the reference monitor. The default password is "`default`", and it can be changed. There are several commands:

- **Change the state of the Reference Monitor**: `state <state> <password>`  
  e.g. `state ON default`

- **Change Password**: `newpass <new_password> <old_password>`  
  e.g. `newpass mynewpass default`

- **Add Path to the blacklist**: `addpath <path> <password>`  
  e.g. `addpath /my/path default`

- **Delete Path from the blacklist**: `deletepath <path> <password>`  
  e.g. `deletepath /my/path default`

Every interaction with the module needs to re-run `sudo ./user`.
Through the `dmesg` command, we can see the interaction with the reference monitor.
