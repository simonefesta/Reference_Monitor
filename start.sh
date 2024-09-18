#!/bin/bash
cd singlefile-FS
make all
make load
make create
make mnt
cd ..
make all
make load
