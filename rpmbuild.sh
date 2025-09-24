#!/bin/bash

if [ $# != 3 ]; then
#echo "please specific the source directory"
    echo "invalid arguments"
    exit
fi

DIR=/tmp/rpmbuild

#cp /usr/lib/rpm/macros /usr/lib/rpm/macros.bak

#sed -i '/^\%_topdir/'d /usr/lib/rpm/macros 2>/dev/null

#echo "%_topdir ${DIR}" >> /usr/lib/rpm/macros
echo "%_topdir ${DIR}" > ~/.rpmmacros
echo '%debug_package %{nil}' >> ~/.rpmmacros

test -d $DIR || mkdir -p $DIR

mkdir -pv ${DIR}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

version=$1
release=$2
src=$3
SPEC="xdrop.spec"
build_dir=${DIR}
target="${build_dir}/SOURCES/xdrop-$version"
sources="${build_dir}/SOURCES/"
RPMS="${build_dir}/RPMS/x86_64"
TOPDIR=`pwd`

test -d $target || mkdir -p $target

rm -rf ${target}/

cp -R $src ${target}/

cd $target

make clean

cd $sources

#sed -i '/^have=PACKAGE_STRING/'d ${sources}/xdrop-${version}/scripts/version 

#echo "have=PACKAGE_STRING value=\"\\\"${version}-${release}\\\"\" . scripts/define" >> ${sources}/xdrop-${version}/scripts/version

tar zcvf xdrop-${version}.tar.gz xdrop-${version}

rm -rf xdrop-${version}

cat   << END                            > $SPEC 

Name:       xdrop 
Version:    ${version} 
Release:    ${release}%{?dist}
Summary:    xdrop 

Group:      Application/Server
License:    GPL 
Packager:   xdrop
Source0:    %{name}-%{version}.tar.gz
BuildRoot:  %_topdir/BUILDROOT
#Prefix:     /usr/local/%{name}

BuildRequires:  gcc,make
#Requires: pcre,pcre-devel,openssl

AutoReqProv: no
%description
xdrop is a packet drop tool

%define installdir /usr/local/%{name}/

%prep
rm -rf %_topdir/BUILD/%{name}-%{version}
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
install -d  %{buildroot}%{installdir}
install -t  %{buildroot}%{installdir} %{installdir}/xdrop
install -t  %{buildroot}%{installdir} %{installdir}/xdrop_kern.obj


%pre

%post

%preun

%postun

%clean
rm -rf %{buildroot}
rm -rf %_topdir/BUILD/%{name}-%{version}

%files
%defattr  (-,root,root,0755)
%{installdir}%{name}
%{installdir}/xdrop_kern.obj

END

rpmbuild -bb $SPEC

cd $TOPDIR

mv ${RPMS}/xdrop-${version}-${release}.el7.x86_64.rpm .

