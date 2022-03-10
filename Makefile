modesdir = modes/
utilsdir = utils/
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -mpclmul -maes -mavx -I$(modesdir) -I$(utilsdir) -O2 -g
# CFLAGS += -DPT_ZEROS
# CFLAGS += -DPT_ZERO_AAD
# CFLAGS += -DPT_64
VPATH = $(modesdir):$(utilsdir)
objects = test.o $(modesdir)gcm_siv.o $(utilsdir)polyval.o $(utilsdir)aes.o
executable = test

all: $(executable)

clean:
	$(RM) $(objects) $(executable)

$(executable): $(objects)
	$(CC) $(objects) -o $(executable)

$(utilsdir)aes.o: aes.h
$(utilsdir)polyval.o: polyval.c
$(modesdir)gcm_siv.o: gcm_siv.c gcm_siv.h modes.h
test.o: test.c aes.h