#!/bin/bash

# Compila il programma
echo "Compiling the program..."
gcc -o unlink_test unlink_test.c

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi


# Esegui il programma

./unlink_test

# Controlla il risultato dell'esecuzione
if [ $? -eq 0 ]; then
    echo "Program executed successfully."
else
    echo "Program execution failed."
    exit 1
fi

