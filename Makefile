# $Header$

ifdef INST
NSHOME ?= $(INST)
else
NSHOME ?= ../aolserver
endif

#
# Module name
#
MOD      =  nssha1.so

#
# Objects to build
#
OBJS     =  nssha1.o

#
# Header files in THIS directory
#
HDRS     =  

#
# Extra libraries
#
MODLIBS  =  

#
# Compiler flags
#
CFLAGS   =  


include  $(NSHOME)/include/Makefile.module
