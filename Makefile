################################################################################
# Copyright (c) 2009 Matthew Anthony Kolybabi (Mak)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
################################################################################

################################################################################
# Variables
################################################################################
BIN	= sha testify
CC	= gcc
CFLAGS	= -Wall -g -std=gnu99 -I ./src
LIBS	= $(OBJ)/sha32.o $(OBJ)/sha64.o
OBJ	= obj
SRC	= src
TESTS	= $(OBJ)/test_null.o $(OBJ)/test_sha1.o $(OBJ)/test_sha224.o \
	  $(OBJ)/test_sha256.o $(OBJ)/test_sha384.o $(OBJ)/test_sha512.o \
	  $(OBJ)/test_sums.o

################################################################################
# Top-Level Targets
################################################################################
all: $(BIN)

sha: $(OBJ)/main_sha.o $(LIBS)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $^

testify: $(OBJ)/main_testify.o $(LIBS) $(TESTS)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $^

clean:
	@echo "[RM] $(BIN)"
	@rm -rf $(BIN)
	@echo "[RM] $(OBJ)"
	@rm -rf $(OBJ)

################################################################################
# Pattern Targets
################################################################################
$(OBJ)/%.o: $(SRC)/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] $@"
	@$(CC) $(CFLAGS) -c -o $@ $^
