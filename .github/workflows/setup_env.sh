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

DOWNLOAD_ROOT=${DOWNLOAD_ROOT:=/download-root}
BUILD_TOOLS_DOWNLOAD=$DOWNLOAD_ROOT/kong-build-tools
BUILD_TOOLS_BRANCH=${BUILD_TOOLS_BRANCH:=master}

if [ ! -d $BUILD_TOOLS_DOWNLOAD ]; then
    git clone -b $BUILD_TOOLS_BRANCH https://github.com/Kong/kong-build-tools.git $BUILD_TOOLS_DOWNLOAD
else
    pushd $BUILD_TOOLS_DOWNLOAD
        git fetch
        git reset --hard origin/$BUILD_TOOLS_BRANCH
    popd
fi

export PATH=$BUILD_TOOLS_DOWNLOAD/openresty-build-tools:$PATH

#--------
# Install
#--------
INSTALL_CACHE=${INSTALL_CACHE:=/install-cache}
INSTALL_ROOT=${INSTALL_ROOT:=/install-root}

kong-ngx-build \
    --work $DOWNLOAD_ROOT \
    --prefix $INSTALL_ROOT \
    --openresty $OPENRESTY \
    --kong-nginx-module ${GITHUB_REF_NAME} \
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

if [ ! -e perl ]; then
    sudo cpanm --notest Test::Nginx > build.log 2>&1 || (cat build.log && exit 1)
    cp -r /usr/local/share/perl/ .
else
    sudo cp -r perl /usr/local/share
fi

nginx -V
resty -V
luarocks --version
openssl version

# Needed by tests of tls.set_upstream_trusted_store
luarocks install lua-resty-openssl
