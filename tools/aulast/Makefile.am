# Makefile.am --
# Copyright 2008,2010,2015 Red Hat Inc.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
# 

SUBDIRS = test
CONFIG_CLEAN_FILES = *.loT *.rej *.orig
EXTRA_DIST = $(man_MANS)
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/auparse
AM_CFLAGS = -D_GNU_SOURCE ${WFLAGS}
bin_PROGRAMS = aulast
noinst_HEADERS = aulast-llist.h
man_MANS = aulast.8

aulast_SOURCES = aulast.c aulast-llist.c
aulast_LDADD = ${top_builddir}/auparse/libauparse.la
aulast_DEPENDENCIES = ${top_builddir}/auparse/libauparse.la
