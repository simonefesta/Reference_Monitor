#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define DEVICE_PATH "/dev/reference_monitor"
#define DIR_TO_REMOVE "directory"

void print_test_description() {
    printf("In this test, the existing directory 'directory' will be protected by the reference monitor.\n");
    printf("The reference monitor is initially set to REC_ON, and the directory is added to the protected paths.\n");
    printf("An attempt to remove the directory will be made first with unlinkat, which should fail.\n");
    printf("Afterward, the directory will be removed from the protected paths using deletepath.\n\n");
}

void send_command(const char *command) {
    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        exit(EXIT_FAILURE);
    }

    printf(">> Sending command: %s\n", command);

    ssize_t bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}

void remove_directory(const char *dir_path) {
    if (rmdir(dir_path) < 0) {
        perror("Error removing directory with rmdir");
    } else {
        printf("Directory '%s' removed successfully.\n", dir_path);
    }
}

int main() {
    print_test_description();

    // Prepara e invia il comando state REC_ON
    char command[256];
    snprintf(command, sizeof(command), "state REC_ON default");
    send_command(command);

    // Prepara e invia il comando addpath
    snprintf(command, sizeof(command), "addpath %s default", DIR_TO_REMOVE);
    send_command(command);

    // Prova a rimuovere la directory con unlinkat
    int dirfd = open(".", O_RDONLY); // Apri la directory corrente
    if (dirfd < 0) {
        perror("Failed to open directory");
        return EXIT_FAILURE;
    }

    if (unlinkat(dirfd, DIR_TO_REMOVE, AT_REMOVEDIR) < 0) {
        perror("Error unlinking the directory with unlinkat (expected)");
    } else {
        printf("Directory '%s' removed successfully (this should not happen if the directory is protected).\n", DIR_TO_REMOVE);
    }

    close(dirfd);

    // Prepara e invia il comando deletepath
    snprintf(command, sizeof(command), "deletepath %s default", DIR_TO_REMOVE);
    send_command(command);

    return EXIT_SUCCESS;
}
