#!/usr/bin/env bash
# set -e

dep_version() {
    grep $1 .requirements | sed -e 's/.*=//' | tr -d '\n'
}

OPENRESTY=$(dep_version RESTY_VERSION)
LUAROCKS=$(dep_version RESTY_LUAROCKS_VERSION)
OPENSSL=$(dep_version RESTY_OPENSSL_VERSION)


#---------
# Download
#---------

DEPS_HASH=$(cat .ci/setup_env.sh .travis.yml .requirements | md5sum | awk '{ print $1 }')
DOWNLOAD_ROOT=${DOWNLOAD_ROOT:=/download-root}
BUILD_TOOLS_DOWNLOAD=$DOWNLOAD_ROOT/kong-build-tools
BUILD_TOOLS_BRANCH=${BUILD_TOOLS_BRANCH:=master}

if [ ! -d $BUILD_TOOLS_DOWNLOAD ]; then
    git clone -b $BUILD_TOOLS_BRANCH -q https://github.com/Kong/kong-build-tools.git $BUILD_TOOLS_DOWNLOAD
else
    pushd $BUILD_TOOLS_DOWNLOAD
        git fetch
        git reset --hard $BUILD_TOOLS_BRANCH
    popd
fi

export PATH=$BUILD_TOOLS_DOWNLOAD/openresty-build-tools:$PATH

#--------
# Install
#--------
INSTALL_CACHE=${INSTALL_CACHE:=/install-cache}
INSTALL_ROOT=$INSTALL_CACHE/$DEPS_HASH

kong-ngx-build \
    --work $DOWNLOAD_ROOT \
    --prefix $INSTALL_ROOT \
    --openresty $OPENRESTY \
    --kong-nginx-module ${TRAVIS_PULL_REQUEST_BRANCH:-$TRAVIS_BRANCH} \
    --luarocks $LUAROCKS \
    --openssl $OPENSSL \
    --debug \
    -j $JOBS

OPENSSL_INSTALL=$INSTALL_ROOT/openssl
OPENRESTY_INSTALL=$INSTALL_ROOT/openresty
LUAROCKS_INSTALL=$INSTALL_ROOT/luarocks

export OPENSSL_DIR=$OPENSSL_INSTALL # for LuaSec install

export PATH=$OPENSSL_INSTALL/bin:$OPENRESTY_INSTALL/nginx/sbin:$OPENRESTY_INSTALL/bin:$LUAROCKS_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$OPENSSL_INSTALL/lib:$LD_LIBRARY_PATH # for openssl's CLI invoked in the test suite

eval `luarocks path`

CPAN_DOWNLOAD=$DOWNLOAD_ROOT/cpanm
mkdir -p $CPAN_DOWNLOAD
wget -O $CPAN_DOWNLOAD/cpanm https://cpanmin.us
chmod +x $CPAN_DOWNLOAD/cpanm
export PATH=$CPAN_DOWNLOAD:$PATH

echo "Installing CPAN dependencies..."
cpanm --notest Test::Nginx &> build.log || (cat build.log && exit 1)
cpanm --notest --local-lib=$TRAVIS_BUILD_DIR/perl5 local::lib && eval $(perl -I $TRAVIS_BUILD_DIR/perl5/lib/perl5/ -Mlocal::lib)

nginx -V
resty -V
luarocks --version
openssl version
