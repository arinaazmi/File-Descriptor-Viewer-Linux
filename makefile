# Makefile for File Descriptor Viewer

CC=gcc


## The default target to compile the whole program
all: showFDtables

## Rule to create the executable
showFDtables: showFDtables.c
	$(CC) -o $@ $^


## Clean the project by removing all the .o files
.PHONY: clean
clean:
	rm -f showFDtables
	rm -f compositeTable.txt
	rm -f compositeTable.bin

.PHONY: help
help:
	@echo "Usage: make [all|clean|help]"
	@echo "all:			Compile the whole program"
	@echo "clean:		Remove all the created files"
	@echo "help:		Display this help message"


