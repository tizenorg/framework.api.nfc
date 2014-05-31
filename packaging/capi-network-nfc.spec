#sbs-git:slp/api/nfc capi-network-nfc 0.0.1 14f15050f8f6ff8217421da04fa5d66e834e2016
Name:       capi-network-nfc
Summary:    A NFC library in SLP C API
Version:    0.0.11
Release:    0
Group:      API/C API
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(nfc)
BuildRequires:  pkgconfig(nfc-common-lib)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(ecore-x)

%description
A NFC library in SLP C API.


%package devel
Summary:  A NFC library in SLP C API -- Development Files
Group:    API/C API
Requires: %{name} = %{version}-%{release}

%description devel
A NFC library in SLP C API.

This package contains the development files for %{name}.


%prep
%setup -q


%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -af LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}

%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest capi-network-nfc.manifest
%{_libdir}/libcapi-network-nfc.so*
/usr/share/license/capi-network-nfc

%files devel
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libcapi-network-nfc.so
