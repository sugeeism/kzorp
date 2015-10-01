Name:                   kzorp
Version:                6.0.6
Release:                1
URL:                    https://www.balabit.com/network-security/zorp-gpl
Source0:                kzorp_%{version}.tar.gz
Summary:                Mixed packet filter/application level gateway, kernel modules
License:                GPL-2.0
Group:                  System/Daemons
BuildRequires:          automake
BuildRequires:          autoconf
BuildRequires:          libtool
BuildRequires:          gcc
BuildRequires:          python

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
Requires(pre):          shadow-utils
BuildRequires:          kernel
BuildRequires:          kernel-devel
BuildRequires:          kmod
Requires(pre):          shadow-utils
%else
Requires(pre):          shadow
Requires(pre):          pwdutils
BuildRequires:          shadow
BuildRequires:          kernel-default-devel
BuildRequires:          kmod-compat
%endif

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
%{!?kernel_release: %global kernel_release %(sh -c "rpm -q kernel-devel | sed 's/kernel-devel-//'")}
%else
%{!?kernel_release: %global kernel_release %(sh -c "rpm -q kernel-default-devel | sed 's/kernel-default-devel-\\([0-9.]\\+-[0-9]\\+\\).*/\\1-default/'")}
%endif

%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

BuildRoot:              %{_tmppath}/%{name}-%{version}-build

%description
Kzorp is a open source set of mechanisms to implement mixed
packet filter/application level gateway functionality on Linux.
Kzorp is used by Zorp, and anyone is welcome to use it with other gateways.

This package provides the binary kernel modules.

%prep
%setup -q -n kzorp

%build
autoreconf -fi
%configure --prefix=/usr
make DESTDIR=${RPM_BUILD_ROOT}
make KERNELRELEASE=%{kernel_release} DESTDIR=${RPM_BUILD_ROOT} -C driver

%install
make DESTDIR=${RPM_BUILD_ROOT} install
make KERNELRELEASE=%{kernel_release} DESTDIR=${RPM_BUILD_ROOT} -C driver install

%files
%dir /lib/modules/%{kernel_release}
%dir /lib/modules/%{kernel_release}/kernel
%dir /lib/modules/%{kernel_release}/kernel/net
%dir /lib/modules/%{kernel_release}/kernel/net/netfilter
/lib/modules/%{kernel_release}/kernel/net/netfilter/*.ko

%pre
getent group zorp >/dev/null || groupadd -r zorp
getent passwd zorp >/dev/null || useradd -r -g zorp -d /var/run/zorp -s /bin/bash -c "user for Zorp" zorp

%package utils
Summary:                Mixed packet filter/application level gateway 
Group:                  Development/Languages

%description utils
Kzorp is a open source set of mechanisms to implement mixed
packet filter/application level gateway functionality on Linux.
Kzorp is used by Zorp, and anyone is welcome to use it with other gateways.

%files utils
%{_sbindir}/kzorp-client
%{_sbindir}/kzorpd
%{_sbindir}/kzorp-stats-updater

%package -n python-kzorp
Summary:                Python bindings for kzorp
Group:                  Development/Languages

%description -n python-kzorp
Zorp is a new generation firewall. It is essentially a transparent proxy
firewall, with strict protocol analyzing proxies, a modular architecture,
and fine-grained control over the mediated traffic. Configuration decisions

General python bindings for kzorp.

%files -n python-kzorp
%dir %{python2_sitelib}/kzorp
%{python2_sitelib}/kzorp/*.py

%dir %{python2_sitelib}/Zorp
%{python2_sitelib}/Zorp/KZorp.py

%if 0%{?fedora} || 0%{?rhel} || 0%{?centos}
%attr(755,root,root) %{python2_sitelib}/Zorp/*.pyc
%attr(755,root,root) %{python2_sitelib}/kzorp/*.pyc
%attr(755,root,root) %{python2_sitelib}/Zorp/*.pyo
%attr(755,root,root) %{python2_sitelib}/kzorp/*.pyo
%endif

%changelog
* Wed Feb 25 2015 BalaBit Zorp GPL Team <zorp@lists.balabit.hu> - 6.0.0-1
- Initial packaging
