#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_PATH "/dev/reference_monitor" // Percorso del dispositivo nel sistema

void print_menu() {
    printf("\n*****************************************\n");
    printf("          The Reference Monitor\n");
    printf("*****************************************\n");
    printf(">> Usage Instructions:\n");
    printf("\n");
    printf("  States:\n");
    printf("    - ON: Enable monitoring\n");
    printf("    - OFF: Disable monitoring\n");
    printf("    - REC_ON: Enable reconfiguration in ON mode\n");
    printf("    - REC_OFF: Disable reconfiguration in OFF mode\n");
    printf("\n");
    printf("  Default Password:\n");
    printf("    - default\n");
    printf("\n");
    printf("  Commands:\n");
    printf("  - Change State:      state <state> <password>                 ; e.g. state ON default\n\n");
    printf("  - Change Password:   newpass <new_password> <old_password>    ; e.g. newpass mynewpass default\n\n");
    printf("  - Add Path:          addpath <path> <password>                ; e.g. addpath /my/path default\n\n");
    printf("  - Delete Path:       deletepath <path> <password>             ; e.g. deletepath /my/path default\n\n");
    printf("  - Exit:              exit\n");
    printf("\n");
    printf("*****************************************\n");
    printf("\n");
}

int main() {
    int fd;
    ssize_t bytes_written;
    char command[100];
    print_menu();

    // Leggi il comando dell'utente
    printf(">> ");
    fgets(command, sizeof(command), stdin);

    // Rimuovi il newline inserito da fgets
    command[strcspn(command, "\n")] = 0;

    // Controlla se l'utente vuole uscire
    if (strcmp(command, "exit") == 0) {
            printf("Exiting...\n");
            return 0;
    }

    // Apri il dispositivo
    fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
            perror("Failed to open the device");
            return 1;
    }

    // Scrivi il comando nel dispositivo
    bytes_written = write(fd, command, strlen(command));
    if (bytes_written < 0) {
            perror("Failed to write to the device");
            close(fd);
            return 1;
    }

    // Chiudi il dispositivo
    close(fd);
    return 0;
}
