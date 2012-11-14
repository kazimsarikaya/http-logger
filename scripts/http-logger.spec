Name:	http-logger	
Version:	0.1
Release:	1%{?dist}
Summary:	an http logger service

Group:		System/Daemons
License:	GPL
URL:		http://projects.sanaldiyar.com/http-logger
Source0:	http-logger-0.1.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:	libconfuse-devel libpcap-devel
Requires:	libpcap libconfuse

%description
A daemon that logs http request on routers for legal operations

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add http-loggerd

%preun
if [ $1 = 0 ]; then
	/sbin/service http-loggerd stop > /dev/null 2>&1
	/sbin/chkconfig --del http-loggerd
fi


%files
%defattr(-,root,root,-)
%doc
/usr/sbin/http-logger
/etc/http-logger.conf
/etc/init.d/http-loggerd
/etc/sysconfig/http-logger

%changelog
