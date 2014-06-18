%global DISTRO_SUSE %(grep VERSION /etc/SuSE-release| sed -e "s/VERSION = /SuSE/"|tr -d ".")

Summary: A milter program for domain authentication technologies
Name: enma
Version: 1.2.0
Release: 1.%{DISTRO_SUSE}
License: BSD
URL: http://enma.sourceforge.net/
Group: Applications/Internet
Source0: enma-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: ldns >= 1.6.0
BuildRequires: sendmail-devel
BuildRequires: openssl-devel >= 0.9.8
Requires: ldns >= 1.6.0
Requires: openssl >= 0.9.8
Requires(post): aaa_base
Requires(preun): aaa_base

%description
ENMA is a program of domain authentication technologies. It authenticates
message senders with SPF, Sender ID, DKIM and/or DKIM ADSP and inserts
the Authentication-Results: field with authentication results.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initrddir}
install -m 755 enma/etc/rc.enma-suse %{buildroot}%{_initrddir}/enma
install -m 644 enma/etc/enma.conf.sample %{buildroot}%{_sysconfdir}/enma.conf

mkdir -p %{buildroot}%{_localstatedir}/run/enma/

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add enma

%preun
if [ $1 = 0 ] ; then
    /sbin/service enma stop > /dev/null 2>&1
    /sbin/chkconfig --del enma
fi

%postun
if [ $1 -ge 1 ] ; then
    /sbin/service enma condrestart > /dev/null 2>&1
fi

%files
%defattr(-, root, root, -)
%doc ChangeLog LICENSE LICENSE.ja README README.ja INSTALL INSTALL.ja
%{_bindir}/*
%{_libdir}/*
%{_libexecdir}/*
%{_mandir}/*/*
%{_mandir}/ja*/*/*
%{_initrddir}/enma
%config %{_sysconfdir}/enma.conf
%attr(0750, daemon, daemon) %dir %{_localstatedir}/run/enma/

%changelog
* Tue Jan 31 2012 KOGA Isamu <koga@iij.ad.jp>
- (1.2.0-1)
- package for openSUSE
