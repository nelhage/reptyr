Name:           reptyr
Version:        0.3
Release:        1%{?dist}
Summary:        A tool for "re-ptying" programs
Group:          Applications/System

License:        MIT
URL:            http://github.com/nelhage/%{name}
#https://github.com/nelhage/%{name}/tarball/%{name}-%{version}
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  arm i386 i486 i586 i686 x86_64
ExclusiveOS:    linux

%if 0%{?rhel} == 5
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%endif

%description
reptyr is a utility for taking an existing running program and
attaching it to a new terminal. Started a long-running process over
ssh, but have to leave and don't want to interrupt it? Just start a
screen, use reptyr to grab it, and then kill the ssh session and head
on home.

%prep
%setup -q


%build
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install PREFIX=/usr DESTDIR=%{buildroot}


%files
%defattr(-,root,root-)
%{_bindir}/%{name}
%{_mandir}/man1/*
%doc COPYING NOTES README ChangeLog

%changelog
* Thu Feb 23 2012 Alex Headley <aheadley@waysaboutstuff.com> 0.3-1
- initial packaging
