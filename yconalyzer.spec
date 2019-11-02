Name:           yconalyzer
Version:        1.0.3
Release:        3%{?dist}
Summary:        TCP Traffic analyzer
Group:          Applications/Internet
License:        BSD
URL:            http://sourceforge.net/projects/yconalyzer/
Source0:        http://sourceforge.net/projects/yconalyzer/files/%{name}-%{version}.tar.bz2

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  gcc-c++
BuildRequires:  libpcap-devel
BuildRequires:  autoconf
BuildRequires:  automake
Requires:       libpcap

%description
Yconalyzer is a low-overhead pcap utility that provides a
bird's eye view of traffic on a particular TCP port,
displaying a distribution of duration, volume and throughput
over all connections while being able to narrow down to a
connection as well.

%prep
%setup -q -n %{name}-%{version}

%build
autoreconf -fi
%configure --prefix=/usr
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR="$RPM_BUILD_ROOT" PREFIX=/usr

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/yconalyzer
%{_mandir}/man8/yconalyzer.8.gz
%doc README INSTALL AUTHORS Changelog

%changelog
* Wed May 26 2010 Naresh <cyan_00391@users.sourceforge.net> - 1.0.3-3
- Initial RPM Build
