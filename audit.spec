Summary: User space tools for kernel auditing
Name: audit
Version: 4.1.2
Release: 1%{dist}
License: GPL-2.0-or-later AND LGPL-2.0-or-later
Group: System Environment/Daemons
URL: https://github.com/linux-audit/audit-userspace/
Source0: https://github.com/linux-audit/audit-userspace/releases/tag/v%{version}.tar.gz
BuildRequires: make gcc
BuildRequires: kernel-headers >= 5.0
BuildRequires: systemd
BuildRequires: autoconf automake libtool

Requires: %{name}-libs = %{version}-%{release}
Requires: %{name}-rules%{?_isa} = %{version}-%{release}
Requires(post): systemd coreutils
Requires(preun): systemd
Requires(postun): systemd coreutils
Recommends: initscripts-service

%description
The audit package contains the user space utilities for
storing and searching the audit records generated by
the audit subsystem in the Linux 2.6 and later kernels.

%package libs
Summary: Dynamic library for libaudit
License: LGPL-2.0-or-later
BuildRequires: libcap-ng-devel

%description libs
The audit-libs package contains the dynamic libraries needed for
applications to use the audit framework.

%package libs-devel
Summary: Header files for libaudit
License: LGPL-2.0-or-later
Requires: %{name}-libs%{?_isa}  = %{version}-%{release}
Requires: kernel-headers >= 5.0

%description libs-devel
The audit-libs-devel package contains the header files needed for
developing applications that need to use the audit framework libraries.

%package libs-static
Summary: Static version of libaudit library
License: LGPL-2.0-or-later
Requires: kernel-headers >= 5.0

%description libs-static
The audit-libs-static package contains the static libraries
needed for developing applications that need to use static audit
framework libraries

%package -n python3-audit
Summary: Python3 bindings for libaudit
License: LGPL-2.0-or-later
BuildRequires: python3-devel python-unversioned-command swig
Requires: %{name}-libs%{?_isa} = %{version}-%{release}
Provides: audit-libs-python3 = %{version}-%{release}

%description -n python3-audit
The audit-libs-python3 package contains the bindings so that libaudit
and libauparse can be used by python3.

%package -n audispd-plugins
Summary: Plugins for the audit event dispatcher
License: GPL-2.0-or-later
BuildRequires: krb5-devel libcap-ng-devel
Requires: %{name} = %{version}-%{release}
Requires: %{name}-libs%{?_isa} = %{version}-%{release}

%description -n audispd-plugins
The audispd-plugins package provides plugins for the real-time
interface to the audit system, audispd. These plugins can do things
like relay events to remote machines or analyze events for suspicious
behavior.

%package -n audispd-plugins-zos
Summary: z/OS plugin for the audit event dispatcher
License: GPL-2.0-or-later
BuildRequires: openldap-devel
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: %{name}-libs%{?_isa} = %{version}-%{release}

%description -n audispd-plugins-zos
The audispd-plugins-zos package provides a plugin that will forward all
incoming audit events, as they happen, to a configured z/OS SMF (Service
Management Facility) database, through an IBM Tivoli Directory Server
(ITDS) set for Remote Audit service.

%package rules
Summary: audit rules and utilities
License: GPL-2.0-or-later
Recommends: %{name} = %{version}-%{release}

%description rules
The audit rules package contains the rules and utilities to load audit rules.

%prep
%setup -q -n %{name}-userspace-%{version}

%build
autoreconf -fv --install
%configure --with-python3=yes --enable-gssapi-krb5=yes \
	   --with-arm --with-aarch64 --with-riscv --with-libcap-ng=yes \
	   --without-golang --enable-zos-remote \
	   --enable-experimental --with-io_uring

make CFLAGS="%{optflags}" %{?_smp_mflags}

%install
mkdir -p $RPM_BUILD_ROOT/{sbin,etc/audit/plugins.d,etc/audit/rules.d}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/{man5,man8}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/audit
mkdir --mode=0700 -p $RPM_BUILD_ROOT/%{_var}/log/audit
mkdir -p $RPM_BUILD_ROOT/%{_var}/spool/audit
make DESTDIR=$RPM_BUILD_ROOT install

find $RPM_BUILD_ROOT -name '*.la' -delete
find $RPM_BUILD_ROOT/%{_libdir}/python%{python3_version}/site-packages -name '*.a' -delete || true

# On platforms with 32 & 64 bit libs, we need to coordinate the timestamp
touch -r ./audit.spec $RPM_BUILD_ROOT/etc/libaudit.conf
touch -r ./audit.spec $RPM_BUILD_ROOT/usr/share/man/man5/libaudit.conf.5.gz

%check
make check
# Get rid of make files so that they don't get packaged.
rm -f rules/Makefile*

%post
%systemd_post auditd.service
# If an upgrade, restart it if it's running
if [ $1 -eq 2 ]; then
    state=$(systemctl show -P ActiveState auditd)
    if [ $state = "active" ] ; then
        auditctl --signal stop || true
        systemctl start auditd || true
    fi
# if an install, start it since preset says we should be running
elif [ $1 -eq 1 ]; then
	systemctl start auditd || true
fi

%post rules
%systemd_post audit-rules.service
# Copy default rules into place on new installation
files=`ls /etc/audit/rules.d/ 2>/dev/null | wc -w`
if [ "$files" -eq 0 ] ; then
	cp %{_datadir}/%{name}-rules/10-base-config.rules /etc/audit/rules.d/audit.rules
	# Fix up permissions
	chmod 0600 /etc/audit/rules.d/audit.rules
	# Make the new rules active
	augenrules --load
fi

%preun
%systemd_preun auditd.service
# If uninstalling, stop it
if [ $1 -eq 0 ]; then
    auditctl --signal stop || true
fi

%preun rules
%systemd_preun audit-rules.service
# If uninstalling, delete the rules loaded in the kernel
if [ $1 -eq 0 ]; then
    auditctl -D > /dev/null 2>&1
fi

%files libs
%license COPYING.LIB
%{_libdir}/libaudit.so.1*
%{_libdir}/libauparse.*
%{_libdir}/libauplugin.so.1*
%config(noreplace) %attr(640,root,root) /etc/libaudit.conf
%{_mandir}/man5/libaudit.conf.5.gz

%files libs-devel
%doc contrib/plugin
%{_libdir}/libaudit.so
%{_libdir}/libauparse.so
%{_libdir}/libauplugin.so
%{_includedir}/libaudit.h
%{_includedir}/audit_logging.h
%{_includedir}/audit-records.h
%{_includedir}/auparse.h
%{_includedir}/auparse-defs.h
%{_includedir}/auplugin.h
%{_datadir}/aclocal/audit.m4
%{_libdir}/pkgconfig/audit.pc
%{_libdir}/pkgconfig/auparse.pc
%{_mandir}/man3/*
%attr(644,root,root) %{_mandir}/man5/ausearch-expression.5.gz

%files libs-static
%license COPYING.LIB
%{_libdir}/libaudit.a
%{_libdir}/libauparse.a
%{_libdir}/libauplugin.a

%files -n python3-audit
%defattr(-,root,root,-)
%attr(755,root,root) %{python3_sitearch}/*

%files
%license COPYING
%doc README.md ChangeLog rules init.d/auditd.cron
%attr(644,root,root) %{_mandir}/man8/auditd.8.gz
%attr(644,root,root) %{_mandir}/man8/aureport.8.gz
%attr(644,root,root) %{_mandir}/man8/ausearch.8.gz
%attr(644,root,root) %{_mandir}/man8/aulast.8.gz
%attr(644,root,root) %{_mandir}/man8/aulastlog.8.gz
%attr(644,root,root) %{_mandir}/man8/ausyscall.8.gz
%attr(644,root,root) %{_mandir}/man5/auditd.conf.5.gz
%attr(644,root,root) %{_mandir}/man5/auditd.cron.5.gz
%attr(644,root,root) %{_mandir}/man5/auditd-plugins.5.gz
%attr(755,root,root) %{_sbindir}/auditd
%attr(755,root,root) %{_sbindir}/ausearch
%attr(755,root,root) %{_sbindir}/aureport
%attr(755,root,root) %{_bindir}/aulast
%attr(755,root,root) %{_bindir}/aulastlog
%attr(755,root,root) %{_bindir}/ausyscall
%attr(640,root,root) %{_tmpfilesdir}/audit.conf
%attr(644,root,root) %{_unitdir}/auditd.service
%attr(750,root,root) %dir %{_libexecdir}/initscripts/legacy-actions/auditd
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/condrestart
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/reload
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/restart
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/resume
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/rotate
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/state
%attr(750,root,root) %{_libexecdir}/initscripts/legacy-actions/auditd/stop
%attr(644,root,root) %{_sysconfdir}/bash_completion.d/audit.bash_completion
%ghost %{_runstatedir}/%{name}/auditd.state
%attr(-,root,-) %dir %{_var}/log/audit
%attr(750,root,root) %dir /etc/audit/plugins.d
%config(noreplace) %attr(640,root,root) /etc/audit/auditd.conf

%files rules
%attr(755,root,root) %dir %{_datadir}/%{name}-rules
%attr(644,root,root) %{_datadir}/%{name}-rules/*
%attr(644,root,root) %{_mandir}/man8/auditctl.8.gz
%attr(644,root,root) %{_mandir}/man8/augenrules.8.gz
%attr(644,root,root) %{_mandir}/man7/audit.rules.7.gz
%attr(755,root,root) %{_sbindir}/auditctl
%attr(755,root,root) %{_sbindir}/augenrules
%attr(644,root,root) %{_unitdir}/audit-rules.service
%attr(750,root,root) %dir /etc/audit
%attr(750,root,root) %dir /etc/audit/rules.d
%ghost %config(noreplace) %attr(640,root,root) /etc/audit/rules.d/audit.rules
%ghost %config(noreplace) %attr(640,root,root) /etc/audit/audit.rules
%config(noreplace) %attr(640,root,root) /etc/audit/audit-stop.rules

%files -n audispd-plugins
%config(noreplace) %attr(640,root,root) /etc/audit/audisp-remote.conf
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/au-remote.conf
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/syslog.conf
%config(noreplace) %attr(640,root,root) /etc/audit/audisp-statsd.conf
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/au-statsd.conf
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/af_unix.conf
%config(noreplace) %attr(640,root,root) /etc/audit/ids.conf
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/audisp-ids.conf
%config(noreplace) %attr(640,root,root) /etc/audit/audisp-filter.conf
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/filter.conf
%attr(644,root,root) %{_datadir}/%{name}-rules/ids-rules/*
%attr(750,root,root) %{_sbindir}/audisp-remote
%attr(750,root,root) %{_sbindir}/audisp-syslog
%attr(750,root,root) %{_sbindir}/audisp-af_unix
%attr(750,root,root) %{_sbindir}/audisp-ids
%attr(750,root,root) %{_sbindir}/audisp-statsd
%attr(750,root,root) %{_sbindir}/audisp-filter
%attr(700,root,root) %dir %{_var}/spool/audit
%attr(644,root,root) %{_mandir}/man5/audisp-remote.conf.5.gz
%attr(644,root,root) %{_mandir}/man8/audisp-remote.8.gz
%attr(644,root,root) %{_mandir}/man8/audisp-syslog.8.gz
%attr(644,root,root) %{_mandir}/man8/audisp-af_unix.8.gz
%attr(644,root,root) %{_mandir}/man8/audisp-statsd.8.gz
%attr(644,root,root) %{_mandir}/man8/audisp-filter.8.gz

%files -n audispd-plugins-zos
%attr(644,root,root) %{_mandir}/man8/audispd-zos-remote.8.gz
%attr(644,root,root) %{_mandir}/man5/zos-remote.conf.5.gz
%config(noreplace) %attr(640,root,root) /etc/audit/plugins.d/audispd-zos-remote.conf
%config(noreplace) %attr(640,root,root) /etc/audit/zos-remote.conf
%attr(750,root,root) %{_sbindir}/audispd-zos-remote

%changelog
Wed Jul 30 2025 Steve Grubb <sgrubb@redhat.com> 4.1.2-1
- New upstream release

