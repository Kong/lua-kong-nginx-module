#!/usr/bin/env bash
# set -e

#---------
# Download
#---------

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

kong-ngx-build \
    --work $DOWNLOAD_ROOT \
    --prefix $INSTALL_ROOT \
    --openresty $OPENRESTY \
    --kong-nginx-module ${GITHUB_BASE_REF:-$GITHUB_REF_NAME} \
    --luarocks $LUAROCKS \
    --openssl $OPENSSL \
    --debug \
    -j $JOBS

export PATH=$LUAROCKS_INSTALL/bin:$PATH

eval `luarocks path`

if [ ! -e perl ]; then
    sudo cpanm --notest Test::Nginx > build.log 2>&1 || (cat build.log && exit 1)
    cp -r /usr/local/share/perl/ .
else
    sudo cp -r perl /usr/local/share
fi

# Needed by tests of tls.set_upstream_trusted_store
luarocks install lua-resty-openssl
