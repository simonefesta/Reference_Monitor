#!/bin/bash

gcc -o append_file_test append_file_test.c

# Verifica se la compilazione ha avuto successo
if [ $? -eq 0 ]; then
   # Esegui il programma con sudo
    sudo ./append_file_test
else
    echo "Compilation failed. Please check the source code for errors."
fi

