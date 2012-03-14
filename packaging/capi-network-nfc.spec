Name:       capi-network-nfc
Summary:    A NFC library in Tizen Native API
Version:    0.0.1
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(nfc)
BuildRequires:  pkgconfig(nfc-common-lib)
BuildRequires:  pkgconfig(capi-base-common)
Requires(post): /sbin/ldconfig  
Requires(postun): /sbin/ldconfig

%description


%package devel
Summary:  A NFC library in Tizen Native API (Development)
Group:    TO_BE/FILLED_IN
Requires: %{name} = %{version}-%{release}

%description devel



%prep
%setup -q


%build
FULLVER=%{version}
MAJORVER=`echo ${FULLVER} | cut -d '.' -f 1`
cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=${FULLVER} -DMAJORVER=${MAJORVER}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%{_libdir}/libcapi-network-nfc.so*

%files devel
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc


