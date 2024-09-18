#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#define DEVICE_PATH "/dev/reference_monitor"
#define MAX_PATH_LENGTH 1024

void print_test_description() {
    printf("In this test, a directory and a file are created. The reference monitor is initially set to REC_ON, and the file is protected.\n");
    printf("An attempt to write to the file will be made first, which should fail, resulting in a log entry on 'the-file'.\n");
    printf("Subsequently, the reference monitor is set to OFF, and a new write attempt will succeed, modifying the file.\n\n");
}


void send_command(const char *command) {
    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        exit(EXIT_FAILURE);
    }

    // Stampa il comando per il debug
    printf(">> Sending command: %s\n", command);

    ssize_t bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
        perror("Failed to write to the device");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}

void modify_file(const char *file_path, const char *message) {
    // Aggiungi una riga al file esistente
    FILE *file = fopen(file_path, "a");
    if (file == NULL) {
        perror("Error opening file for appending");
        printf("File not modified.\n");
        return; // Esci dalla funzione se non si può aprire il file
    }

    fprintf(file, "%s\n", message);
    fclose(file);

    // Solo se la scrittura e la chiusura del file sono andate a buon fine
    printf("File modified successfully.\n");
}


int main() {
    print_test_description();
    char cwd[MAX_PATH_LENGTH];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("Error getting current working directory");
        return EXIT_FAILURE;
    }

    char dir_path[MAX_PATH_LENGTH];
    if (snprintf(dir_path, sizeof(dir_path), "%s/directory", cwd) >= sizeof(dir_path)) {
        fprintf(stderr, "Error: Directory path is too long\n");
        return EXIT_FAILURE;
    }
    
    char file_path[MAX_PATH_LENGTH];
    if (snprintf(file_path, sizeof(file_path), "%s/directory/file1.txt", cwd) >= sizeof(file_path)) {
        fprintf(stderr, "Error: File path is too long\n");
        return EXIT_FAILURE;
    }

    // Prepara e invia il comando state REC_ON
    char command[MAX_PATH_LENGTH];

    if (snprintf(command, sizeof(command), "state REC_ON default") >= sizeof(command)) {
        fprintf(stderr, "Error: State command is too long\n");
        return EXIT_FAILURE;
    }
    send_command(command);

    // Prepara e invia il comando addpath
    if (snprintf(command, sizeof(command), "addpath %s default", dir_path) >= sizeof(command)) {
        fprintf(stderr, "Error: Addpath command is too long\n");
        return EXIT_FAILURE;
    }
    send_command(command);

    // Prova a modificare il file
    modify_file(file_path, "If you're reading this in file1.txt, test FAILED.");

    // Prepara e invia il comando state OFF
    if (snprintf(command, sizeof(command), "state OFF default") >= sizeof(command)) {
        fprintf(stderr, "Error: State command is too long\n");
        return EXIT_FAILURE;
    }
    send_command(command);

    // Prova a scrivere una frase diversa nel file
    modify_file(file_path, "If you're reading this in file1.txt, test PASSED.");

    if (snprintf(command, sizeof(command), "state REC_ON default") >= sizeof(command)) {
        fprintf(stderr, "Error: State command is too long\n");
        return EXIT_FAILURE;
    }
    send_command(command);

    // Prepara e invia il comando removepath
    if (snprintf(command, sizeof(command), "deletepath %s default", dir_path) >= sizeof(command)) {
        fprintf(stderr, "Error: Addpath command is too long\n");
        return EXIT_FAILURE;
    }
    send_command(command);

    return EXIT_SUCCESS;
}
