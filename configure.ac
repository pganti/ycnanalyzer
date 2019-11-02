#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#

#
# Software Copyright License Agreement (BSD License)
# 
# Copyright (c) 2010, Yahoo! Inc.
# All rights reserved.
# 
# Redistribution and use of this software in source and binary forms, 
# with or without modification, are permitted provided that the following 
# conditions are met:
# 
# * Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
# 
# * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
# 
# * Neither the name of Yahoo! Inc. nor the names of its
#   contributors may be used to endorse or promote products
#   derived from this software without specific prior
#   written permission of Yahoo! Inc.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS 
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
#


AC_INIT([yconalyzer], [1.0.3], [yconalyzer@sf.net])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
AC_SUBST(PACKAGE_LIBS)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([pcap.h])
AC_CHECK_HEADERS([dlfcn.h])
AC_HEADER_STDBOOL

# Check for the dlopen
DL_LIB=
AC_CHECK_LIB(dl, dlopen, [
     DL_LIB="-ldl"
     AC_DEFINE(HAVE_DLOPEN, 1, [Define if dlopen is known in -ldl library])
   ],
   [
     AC_CHECK_LIB(dld, shl_load, [
        DL_LIB="-ldld"
        AC_DEFINE(HAVE_DLOPEN, 1, [Define if dlopen is known in -ldld library])
     ],
     [
        AC_CHECK_FUNCS(dlopen, DL_LIB="",AC_MSG_WARN(Dynamic linking is not available on this platform. Skipping it.))
     ])
   ]
)

oLIBS="$LIBS"
LIBS="$LIBS $DL_LIB"
LIBS="$oLIBS"
AC_SUBST(DL_LIB)


# Check for the lpcap and pcap_breakloop if pcap library is found
PCAP_LIB=
AC_CHECK_FUNCS(pcap_open_live,,[
  AC_CHECK_LIB(pcap, pcap_open_live,[
     PCAP_LIB="-lpcap"
     AC_DEFINE(HAVE_PCAP_OPEN_LIVE, 1, [Define if pcap_open_live is known])
     AC_CHECK_FUNCS([pcap_breakloop],,[
        AC_CHECK_LIB(pcap, pcap_breakloop,AC_DEFINE(HAVE_PCAP_BREAKLOOP, 1, [Define if pcap_breakloop is known]))
     ])
  ], AC_MSG_ERROR(pcap library is not available on this platform.))
])


oLIBS="$LIBS"
LIBS="$LIBS $PCAP_LIB"
LIBS="$oLIBS"
AC_SUBST(PCAP_LIB)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
#AC_TYPE_UINT16_T
AC_C_CONST
AC_STRUCT_TM
AC_TYPE_SIGNAL

# Checks for library functions.
AC_FUNC_MKTIME
AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([siginterrupt])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
