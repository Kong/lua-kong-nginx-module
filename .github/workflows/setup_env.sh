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
if [[ -z $BORINGSSL ]]; then
    kong-ngx-build \
        --work $DOWNLOAD_ROOT \
        --prefix $INSTALL_ROOT \
        --openresty $OPENRESTY \
        --kong-nginx-module ${GITHUB_HEAD_REF:-$GITHUB_REF_NAME} \
        --luarocks $LUAROCKS \
        --openssl $OPENSSL \
        --debug \
        -j $JOBS
else
    # libtinfo5 is a dependency of clang7 on ubuntu20.04
    sudo apt-get install -qq -y cmake libtinfo5 unzip libunwind-dev libgcc-7-dev libstdc++-7-dev

    pushd $DOWNLOAD_ROOT
    if [[ ! -f tools_downloaded ]]; then
        # clang
        wget https://releases.llvm.org/7.0.1/clang+llvm-7.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz -qO - |tar Jxf -
        if [[ -z $HOME ]]; then
            export HOME="$PWD"
        fi
        printf "set(CMAKE_C_COMPILER \"clang\")\nset(CMAKE_CXX_COMPILER \"clang++\")\n" > ${HOME}/toolchain
        # export PATH="$PWD/clang+llvm-7.0.1-x86_64-linux-gnu-ubuntu-18.04/bin:$PATH"
        # overwrite any system clang if needed
        sudo ln -sf $PWD/clang+llvm-7.0.1-x86_64-linux-gnu-ubuntu-18.04/bin/* /usr/bin/
        clang --version

        # go
        wget https://dl.google.com/go/go1.12.7.linux-amd64.tar.gz -qO - |tar zxf -
        export GOPATH="$PWD/gopath"
        export GOROOT="$PWD/go"
        export PATH="$GOPATH/bin:$GOROOT/bin:$PATH"
        go version

        # ninja
        wget https://github.com/ninja-build/ninja/releases/download/v1.9.0/ninja-linux.zip -q
        unzip -o ninja-linux.zip
        export PATH="$PWD:$PATH"
        ninja --version

        touch tools_downloaded
    fi
    popd

    kong-ngx-build \
        --work $DOWNLOAD_ROOT \
        --prefix $INSTALL_ROOT \
        --openresty $OPENRESTY \
        --kong-nginx-module ${GITHUB_HEAD_REF:-$GITHUB_REF_NAME} \
        --luarocks $LUAROCKS \
        --boringssl $BORINGSSL \
        --debug \
        -j $JOBS
fi

export PATH=$OPENSSL_INSTALL/bin:$OPENRESTY_INSTALL/nginx/sbin:$OPENRESTY_INSTALL/bin:$LUAROCKS_INSTALL/bin:$PATH

eval `luarocks path`

if [ ! -e perl ]; then
    sudo cpanm --notest Test::Nginx > build.log 2>&1 || (cat build.log && exit 1)
    cp -r /usr/local/share/perl/ .
else
    sudo cp -r perl /usr/local/share
fi

# Needed by tests of tls.set_upstream_trusted_store
luarocks install lua-resty-openssl
