TOP=../..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

USR_CXXFLAGS += -std=c++11

#==================================================
# bldDecode

PROD += bldDecode

bldDecode_SRCS += bldDecode.cc

bldDecode_LIBS += pvxs Com
INC += bld-proto.h
bldDecode_CFLAGS += -Wall

#==================================================

#==================================================
# bldSend

PROD += bldSend
bldSend_SRCS += bldSend.cc
bldSend_CFLAGS += -Wall

#==================================================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

