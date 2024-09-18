#!/bin/bash
cd singlefile-FS
make clean
make remove
cd ..
make unload
make clean
rm user

