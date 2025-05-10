#!/bin/bash

# Check if the script is running as root
if [ "$EUID" -ne 0 ]; then
    # Comment out the following line if you do not want to automatically re-run the script:
    exec sudo "$0" "$@"
    # echo -e "\e[1;34mThis script must be run as root.\e[0m"
    # exit 1
fi

echo
echo -e "\e[1;37m ##### Generate OpenSSL Self Signed CA Certificates & Keys for PacketGo Dynamic Proxy ##### \e[0m"

WORKSPACE=$(pwd)

# NGINX_VER="1.15.8"
# NGINX_VER="1.21.4"
NGINX_VER="1.25.3"
OPENRESTY_VER="openresty-${NGINX_VER}.2"

PROXY_PREFIX="/usr/local"
OPENRESTY_PATH="${PROXY_PREFIX}/openresty"
#############################################################################
# nginx path prefix         : "/usr/local/openresty/nginx"                  #
# nginx binary file         : "/usr/local/openresty/nginx/sbin/nginx"       #
# nginx modules path        : "/usr/local/openresty/nginx/modules"          #
# nginx configuration path  : "/usr/local/openresty/nginx/conf"             #
# nginx configuration file  : "/usr/local/openresty/nginx/conf/nginx.conf"  #
#                             "/usr/local/openresty/nginx/sites-available"  #
#                             "/usr/local/openresty/nginx/sites-enabled"    #
# nginx pid path            : "/usr/local/openresty/nginx/logs/nginx.pid"   #
# nginx log path            : "/var/log/openresty/*.log"                    #
#############################################################################
NGINX_PATH="${OPENRESTY_PATH}/nginx"
NGINX_CONF_PATH="${NGINX_PATH}/conf"
NGINX_CONF_SITES_AVAILABLE_PATH="${NGINX_PATH}/sites-available"
NGINX_CONF_SITES_ENABLED_PATH="${NGINX_PATH}/sites-enabled"
NGINX_PID_PATH="${NGINX_PATH}/logs"
NGINX_LOG_PATH="/var/log/openresty"

EXTERN_LIB_PATH="${NGINX_PATH}/lib"

# NOTE.
# Refer to "https://github.com/chobits/ngx_http_proxy_connect_module#select-patch"
# proxy_connect_rewrite_<VERSION>.patch enables these REWRITE phase directives.
# To add a custom header, such as "X-PRIBIT-PARAM," to the request header, 
# we should use the rewrite_by_lua directive.
patch_ngx_http_proxy_connect_module() {
    local PATCH_TARGET="${WORKSPACE}/modules/ngx_http_proxy_connect_module/patch/proxy_connect_rewrite_102101.patch"
    local BUNDLE_PATH="${WORKSPACE}/${OPENRESTY_VER}/bundle"

    if [ -d "$BUNDLE_PATH" ]; then
        if [ ! -f "${BUNDLE_PATH}/nginx-${NGINX_VER}/src/http/ngx_http_core_module.c.rej" ]; then
            echo
            echo -e "\e[32m> Patching \"${PATCH_TARGET}\" into nginx source \e[0m"
            patch -d "${BUNDLE_PATH}/nginx-${NGINX_VER}" -p1 < "${PATCH_TARGET}"
            # patch -d "${WORKSPACE}/${OPENRESTY_VER}/build/nginx-"*/ -p1 < "${PATCH_TARGET}"
            # Check execution results
            if [ $? -eq 0 ]; then
                cp -f "${PATCH_TARGET}" "${BUNDLE_PATH}/nginx-${NGINX_VER}/src/http/ngx_http_core_module.c.rej"
            else
                echo -e "\e[31m> Failed to patch \"${MSC_MODULE_SRCS[${i}]}\" \e[0m"
                exit 1
            fi
        else
            echo
            echo -e "\e[1;2m> Patching skipped: Either patch file doesn't exist or a reject file already exists. \e[0m"
        fi
    else
        echo
        echo -e "\e[31m> The directory \"${BUNDLE_PATH}\" does not exist. \e[0m"
    fi
}

patch_resty_redis_for_redisjaon() {
    local PATCH_PATH="${WORKSPACE}/patches"
    local PATCH_TARGET="${PATCH_PATH}/pg_redis_for_json_20231112.patch"
    local RESTY_DIR="${WORKSPACE}/${OPENRESTY_VER}/bundle/lua-resty-redis-0.30/lib/resty"
    local REDIS_LUA="${RESTY_DIR}/redis.lua"
    local REDIS_LUA_REJ="${REDIS_LUA}.rej"

    if [ -d "${RESTY_DIR}" ]; then
        if [ -f "${PATCH_TARGET}" ] && [ ! -f "${REDIS_LUA_REJ}" ]; then
            echo
            echo -e "\e[32m> Patching \"${PATCH_TARGET}\" into \"${REDIS_LUA}\" \e[0m"
            patch -d "${RESTY_DIR}" -p0 < "${PATCH_TARGET}"
            # Check execution results
            if [ $? -eq 0 ]; then
                cp -f "${PATCH_TARGET}" "${REDIS_LUA_REJ}"
            else
                echo -e "\e[31m> Failed to patch \"${MSC_MODULE_SRCS[${i}]}\" \e[0m"
                exit 1
            fi
        else
            echo
            echo -e "\e[1;2m> Patching skipped: Either patch file doesn't exist or a reject file already exists. \e[0m"
        fi
    else
        echo
        echo -e "\e[31m> The directory \"${RESTY_DIR}\" does not exist for patching. \e[0m"
    fi
}

install_luarocks() {
    local LUAROCKS_VER="3.11.1"
    if [ ! -f "${OPENRESTY_PATH}/luajit/bin/luarocks" ]; then
        if [ ! -d "${WORKSPACE}/luarocks-${LUAROCKS_VER}" ]; then
            if [ ! -f "${WORKSPACE}/archives/luarocks-${LUAROCKS_VER}.tar.gz" ]; then
                echo -e "\e[32m> Download \"luarocks-${LUAROCKS_VER}.tar.gz\" \e[0m"
                wget --no-check-certificate https://luarocks.github.io/luarocks/releases/luarocks-${LUAROCKS_VER}.tar.gz -O "${WORKSPACE}/archives/luarocks-${LUAROCKS_VER}.tar.gz"
            fi
            tar zxpf "${WORKSPACE}/archives/luarocks-${LUAROCKS_VER}.tar.gz" -C "${WORKSPACE}"
        fi

        if [ -d "${WORKSPACE}/luarocks-${LUAROCKS_VER}" ]; then
            echo -e "\e[32m> Install \"${OPENRESTY_PATH}/luajit/bin/luarocks\" \e[0m"
            cd "${WORKSPACE}/luarocks-${LUAROCKS_VER}" || exit
            ./configure --prefix="${OPENRESTY_PATH}/luajit" \
                        --with-lua="${OPENRESTY_PATH}/luajit/" \
                        --lua-suffix=jit \
                        --with-lua-include="${OPENRESTY_PATH}/luajit/include/luajit-2.1/"
            make
            make install
            ${OPENRESTY_PATH}/luajit/bin/luarocks install md5
            cd "${WORKSPACE}"
            rm -rf "${WORKSPACE}/luarocks-${LUAROCKS_VER}" "${WORKSPACE}/archives/luarocks-${LUAROCKS_VER}.tar.gz"
        fi
    fi
}

LUA_PACKAGES=("lua-resty-http" \
              "lua-resty-openssl" \
              "lua-resty-logger-socket" \
              "luaposix" \
              "luasocket" \
              "luasec")

uninstall_luarocks_n_packages_for_strmproxy() {
    for PKG in "${LUA_PACKAGES[@]}"; do
        if [ -f "${OPENRESTY_PATH}/luajit/bin/luarocks" ]; then
            echo -e "\e[3;33m> ${OPENRESTY_PATH}/luajit/bin/luarocks remove \e[0;1m\"${PKG}\" \e[0m"
            ${OPENRESTY_PATH}/luajit/bin/luarocks remove ${PKG}
        fi
    done
}

install_luarocks_n_packages_for_strmproxy() {
    echo
    echo -e "\e[32m> Install \e[1mluarocks & lua packages\e[0m"

    install_luarocks

    if [ -f "${OPENRESTY_PATH}/luajit/bin/luarocks" ]; then
        for PKG in "${LUA_PACKAGES[@]}"; do
            echo -e "\e[33m> ${OPENRESTY_PATH}/luajit/bin/luarocks install \e[0;1m\"${PKG}\" \e[0m"
            ${OPENRESTY_PATH}/luajit/bin/luarocks install ${PKG}
        done
    fi
}

check_dependencies() {
    OS=$(sed -n -e '/PRETTY_NAME/ s/^.*=\|"\| .*//gp' /etc/os-release)

    if [[ ${OS} == "Ubuntu" ]] && [[ ! -e "${NGINX_PATH}" ]]; then
        echo
        echo -e "\e[32m> Check Dependencies for ${OS} \e[0m"
        local PACKAGES=("build-essential" "wget" "git" "cmake" "autoconf" "automake" "checkinstall" \
                        "flex" "bison" "dh-autoreconf" "libtool" "pkgconf" "zip" "unzip" "ssdeep" \
                        "zlibc" "zlib1g" "zlib1g-dev" "libxml2" "libxml2-dev" \
                        "libcurl4" "libcurl4-openssl-dev" \
                        "libpcre2-16-0" "libpcre2-dev" "libpcre3" "libpcre3-dev" "libpcre++-dev" \
                        "ssdeep" "libfuzzy2" "libfuzzy-dev" \
                        "libgeoip-dev" "liblmdb-dev" "libyajl-dev" \
                        "acl")

        # Check if OpenSSL and its headers are installed
        if ! command -v openssl &>/dev/null || [[ ! -f /usr/local/include/openssl/opensslv.h ]]; then
            PACKAGES+=("openssl" "libssl-dev")
        fi

        for PKG in "${PACKAGES[@]}"; do
            if ! dpkg -l | grep -q "^ii\s\+${PKG}"; then
                echo -e "\e[32mInstalling \e[1m${PKG}\e[0m"
                if apt-get install -y "${PKG}"; then
                    echo -e "\e[32m${PKG} installed successfully\e[0m"
                else
                    echo -e "\e[31mFailed to install ${PKG}\e[0m"
                fi
            else
                echo -e "\e[1m${PKG}\e[0;32m is already installed\e[0m"
            fi
        done

        if ! which gmake &>/dev/null; then
            ln -vs -T /usr/bin/make /usr/bin/gmake
        fi
    fi

    local SUBDIRS=("archives" "modules")
    for subdir in "${SUBDIRS[@]}"; do
        mkdir -pv "${WORKSPACE}/$subdir"
    done

    if [ ! -d "${WORKSPACE}/modules/ngx_http_proxy_connect_module" ]; then
        echo
        echo -e "\e[32m> Download \"${WORKSPACE}/modules/ngx_http_proxy_connect_module\" \e[0m"
        local NGX_HTTP_CONNECT_MODULE_DN="https://github.com/chobits/ngx_http_proxy_connect_module.git"
        git clone ${NGX_HTTP_CONNECT_MODULE_DN} ${WORKSPACE}/modules/ngx_http_proxy_connect_module
    else
        echo
        echo -e "\e[32m> Check update ${WORKSPACE}/modules/ngx_http_proxy_connect_module \e[0m"
        cd ${WORKSPACE}/modules/ngx_http_proxy_connect_module
        local_commit=$(git rev-parse HEAD)
        current_branch=$(git rev-parse --abbrev-ref HEAD)
        remote_commit=$(git ls-remote origin -h refs/heads/$current_branch | cut -f1)
        if [ "$local_commit" != "$remote_commit" ]; then
            echo -e "\e[32m> Pulling changes... \e[0m"
            git pull
        fi
        cd ${WORKSPACE}
    fi

    if [ ! -d "${WORKSPACE}/${OPENRESTY_VER}" ]; then
        if [ ! -f "${WORKSPACE}/archives/${OPENRESTY_VER}.tar.gz" ]; then
            echo
            echo -e "\e[32m> Download \"${OPENRESTY_VER}.tar.gz\" \e[0m"
            local OPENRESTY_DN="https://openresty.org/download/${OPENRESTY_VER}.tar.gz"
            wget --no-check-certificate ${OPENRESTY_DN} -O ${WORKSPACE}/archives/${OPENRESTY_VER}.tar.gz
        fi
        tar zxpf ${WORKSPACE}/archives/${OPENRESTY_VER}.tar.gz -C ${WORKSPACE}
    fi

    # Patch Nginx for ngx_http_proxy_connect_module
    patch_ngx_http_proxy_connect_module
    # Pribit's custom Patch for JSON queries in OpenResty's Redis
    patch_resty_redis_for_redisjaon

    if [ ! -d "/www" ]; then
        mkdir -vp "/www/pktgo"
    fi

    echo

    usermod -aG sudo www-data
    # Check if www-data is set in sudoers file
    if ! grep -q "^www-data.*NOPASSWD: ALL" /etc/sudoers; then
        # Add www-data NOPASSWD: ALL to the setting
        echo "Add \"www-data NOPASSWD: ALL\" to /etc/sudoers"
        echo "www-data ALL=NOPASSWD: ALL" | tee -a /etc/sudoers > /dev/null
        if [ $? -ne 0 ]; then
            echo "Failed to add \"www-data NOPASSWD: ALL\" to /etc/sudoers"
            exit 1
        fi
    fi

    if [ -d "/www" ]; then
        echo -e "\e[32m> Change ownership and permissions of /www \e[0m"
        if ! getfacl "/www" | grep -qw "pribit"; then
            # Set ownership and permissions for pribit
            ## Set read and write permissions for newly created directories and files.
            setfacl -Rdm u:pribit:rwx,g:pribit:rwx "/www"
            setfacl -Rdm u:www-data:rwx,g:www-data:rwx "/www"
            ## Set read and write permissions for existing directories and files.
            setfacl -Rm u:pribit:rwx,g:pribit:rwx "/www"
            setfacl -Rm u:www-data:rwx,g:www-data:rwx "/www"
        fi

        # echo
        # echo "> ACL settings for /www directory:"
        # getfacl /www
    fi
    
    if [ ! -d "${NGINX_LOG_PATH}" ]; then
        mkdir -p "${NGINX_LOG_PATH}"
    fi
    if ! getfacl "${NGINX_LOG_PATH}" | grep -qw "www-data"; then
        echo -e "\e[32m> Change ownership and permissions of ${NGINX_LOG_PATH} \e[0m"
        echo "> Adding user 'www-data' to the 'root' group."
        setfacl -Rdm u:www-data:rwx,g:www-data:rwx ${NGINX_LOG_PATH}
        setfacl -Rm u:www-data:rwx,g:www-data:rwx ${NGINX_LOG_PATH}
    fi

    # if command -v redis-server &> /dev/null; then
    #     # redis.conf path
    #     REDIS_CONF="/etc/redis/redis.conf"

    #     # Check if /etc/redis/redis.conf exists.
    #     if [ -f "$REDIS_CONF" ]; then
    #         if ! grep -q "^unixsocket " "$REDIS_CONF"; then
    #             echo
    #             echo -e "\e[32m> Enable Redis Unix socket \e[0m"
    #             CURRENT_DATE=$(date +%Y%m%d)
    #             sudo cp "$REDIS_CONF" "$REDIS_CONF.bak.${CURRENT_DATE}"
    #             if grep -q "^# unixsocket " "$REDIS_CONF"; then
    #                 # enable unix socket
    #                 sudo sed -i "s|^# unixsocket .*|unixsocket /var/run/redis/redis-server.sock|" "$REDIS_CONF"
    #                 sudo sed -i "s|^# unixsocketperm .*|unixsocketperm 770|" "$REDIS_CONF"
    #             fi

    #             echo "> Adding user 'www-data' to the 'redis' group."
    #             setfacl -Rdm u:www-data:rwx,g:www-data:rwx /var/run/redis
    #             setfacl -Rm u:www-data:rwx,g:www-data:rwx /var/run/redis
                
    #             # restart redis-server
    #             sudo systemctl restart redis-server
    #         fi
    #     fi
    # fi
}

config() {
    echo
    if [ ! -d "${WORKSPACE}/${OPENRESTY_VER}" ]; then
        echo -e "\e[31m> No such file or directory: ${WORKSPACE}/${OPENRESTY_VER} \e[0m"
        exit 1
    fi
    cd ${WORKSPACE}/${OPENRESTY_VER}

    if [ -d "./build" ]; then
        clean
    fi

    echo -e "\e[32m> Configure \e[0m"
    PG_LIBSSL_PATH="/usr/local/lib64"
    ./configure \
        --prefix="${OPENRESTY_PATH}" \
        --http-log-path="${NGINX_LOG_PATH}/access.log" \
        --error-log-path="${NGINX_LOG_PATH}/error.log" \
        --with-compat \
        --with-threads \
        --with-file-aio \
        --with-pcre-jit \
        --with-http_gzip_static_module \
        --with-http_secure_link_module \
        --with-http_geoip_module \
        --with-http_dav_module \
        --with-http_realip_module \
        --with-http_slice_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_stub_status_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-cc-opt="-g -O3 -std=gnu99 -fstack-protector-strong \
                       -DNGX_LUA_USE_ASSERT -DNGX_LUA_ABORT_AT_PANIC \
                       -Wall -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2 \
                       -Wno-unused-but-set-parameter \
                       -Wno-unused-but-set-variable \
                       -Wno-unused-variable \
                       -Wno-unused-function \
                       -Wno-unused-value" \
        --with-ld-opt="-L${PG_LIBSSL_PATH} \
                       -L${EXTERN_LIB_PATH} \
                       -Wl,-rpath,${EXTERN_LIB_PATH} \
                       -Wl,-Bsymbolic-functions \
                       -Wl,-z,relro \
                       -Wl,-z,now \
                       -Wl,--no-undefined \
                       -Wl,--as-needed \
                       -fPIC" \
        --add-module="${WORKSPACE}/modules/ngx_http_proxy_connect_module"
        # --with-debug
}

build() {
    if [ ! -d "${WORKSPACE}/${OPENRESTY_VER}" ]; then
        echo -e "\e[31m> No such file or directory: ${WORKSPACE}/${OPENRESTY_VER} \e[0m"
        exit 1
    fi
    cd ${WORKSPACE}/${OPENRESTY_VER}
    
    # Build
    echo
    echo -e "\e[32m> Build \e[0m"
    gmake -j$(nproc)
    # Check execution results
    if [ $? -ne 0 ]; then
        echo -e "\e[31m> Failed to make -j$(nproc). exit with $? \e[0m"
        exit 1
    fi
}

clean() {
    if [ -d "${WORKSPACE}/${OPENRESTY_VER}" ]; then
        cd ${WORKSPACE}/${OPENRESTY_VER}
        if [ -e "./Makefile" ]; then
            echo
            echo -e "\e[32m> Clean \e[0m"
            gmake clean > /dev/null 2>&1
            rm -vf Makefile
        fi
    # else
    #     echo -e "\e[31m> No such file or directory: ${WORKSPACE}/${OPENRESTY_VER} \e[0m"
    fi
}

stop_openresty_nginx() {
    if systemctl is-active --quiet openresty.service; then
        systemctl stop openresty.service
        systemctl disable openresty.service
        systemctl daemon-reload
    fi

    if [ -f "${NGINX_PID_PATH}/nginx.pid" ]; then
        local NGINX_PID=$(cat ${NGINX_PID_PATH}/nginx.pid)
        if [ ! -z "${NGINX_PID}" ]; then
            echo
            echo -e "> Shutting down the NGINX \e[1m\"${NGINX_PATH}\"\e[0m"
            ${NGINX_PATH}/sbin/nginx -p ${NGINX_PATH} -s stop
            sleep 1
        fi
    fi
}

install() {
    if [ ! -d "${WORKSPACE}/${OPENRESTY_VER}" ]; then
        echo -e "\e[31m> No such file or directory: ${WORKSPACE}/${OPENRESTY_VER} \e[0m"
        exit 1
    fi
    cd ${WORKSPACE}/${OPENRESTY_VER}

    # Install
    echo
    echo -e "\e[32m> Install \"$NGINX_PATH\"\e[0m"
    
    stop_openresty_nginx

    gmake install
    # Check execution results
    if [ $? -ne 0 ]; then
        echo -e "\e[31m> Failed to make install. exit with ${install_exit_status} \e[0m"
        exit 1
    fi

    echo

    copy_nginx_conf_n_lua
}

uninstall() {
    # Uninstall
    echo
    PROMPT_MESSAGE="\e[32m> Uninstall now \e[1m\"${NGINX_PATH}\"\e[0m? (y/N): "
    read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
    USER_RESPONSE=${USER_RESPONSE:-"N"}
    case "$USER_RESPONSE" in
        1|y|Y)
            stop_openresty_nginx

            clean

            # Remove openresty-related files in WORKSPACE
            echo "Removing openresty files from ${WORKSPACE}..."
            find "${WORKSPACE}" -name 'openresty-*' -exec rm -rf {} \;
            find "${WORKSPACE}/modules" -name "ngx_http_proxy_connect_module" -exec rm -rf {} \;

            echo "Removing openresty and related files from system directories..."
            find "${PROXY_PREFIX}" /etc /usr /var -name "openresty*" -exec rm -rf {} \;
            find /etc -name "resty-auto-ssl*" -exec rm -rf {} \;

            if [ -d "/www" ]; then
                # Delete ownership and permissions for pribit
                ## Delete read and write permissions for newly created directories and files.
                setfacl -Rdx u:pribit,g:pribit /www
                ## Delete read and write permissions for existing directories and files.
                setfacl -Rx u:pribit,g:pribit /www

                # echo
                # echo "ACL settings for /www directory:"
                # getfacl /www

                # Safely remove all files and directories within /www
                find /www -mindepth 1 -delete
            fi
            ;;
        *)
            ;;
    esac
}

copy_files() {
    local SRC_DIR="$1"
    local DST_DIR="$2"

    if [ ! -d "$DST_DIR" ]; then
        mkdir -p "$DST_DIR" || { echo "Failed to create directory $DST_DIR"; exit 1; }
    fi

    # Recursively copy files and directories from source to destination
    for item in "$SRC_DIR"/*; do
        local ITEM_NAME=$(basename "$item")
        local TARGET="$DST_DIR/$ITEM_NAME"

        if [ -d "$item" ]; then
            # If it's a directory, recursively copy its contents
            copy_files "$item" "$TARGET"
        else
            # If it's a file, copy it if it doesn't exist or has different contents
            if [ -e "$TARGET" ]; then
                if ! cmp -s "$item" "$TARGET"; then
                    # echo "Updating file: $TARGET"
                    cp -fv "$item" "$TARGET" || { echo "Failed to copy $item to $TARGET"; exit 1; }
                # else
                #     echo "No changes for file: $TARGET"
                fi
            else
                # echo "Copying new file: $TARGET"
                cp -fv "$item" "$TARGET" || { echo "Failed to copy $item to $TARGET"; exit 1; }
            fi
        fi
    done
}

copy_nginx_conf_n_lua() {
    echo
    echo -e "\e[32m> Copy configurations & source \e[0m"
    if [ -d "${NGINX_CONF_PATH}" ]; then
        if [ ! -f "${NGINX_CONF_PATH}/nginx.conf.default" ]; then
            echo
            echo -e "\e[32m> Copy nginx.conf for backup \e[0m"
            # Backup nginx.conf as default
            cp -v ${NGINX_CONF_PATH}/nginx.conf{,.default}
        fi

        if [ -f "${WORKSPACE}/conf/pktgo_nginx.conf" ] && 
             ! cmp -s "${WORKSPACE}/conf/pktgo_nginx.conf" "${NGINX_CONF_PATH}/nginx.conf"; then
            echo
            echo -e "\e[32m> Copy nginx.conf \e[0m"
            cp -vf ${WORKSPACE}/conf/pktgo_nginx.conf ${NGINX_CONF_PATH}/nginx.conf
        fi

        echo
        mkdir -vp "${NGINX_CONF_SITES_AVAILABLE_PATH}"
        if [ -d "${NGINX_CONF_SITES_AVAILABLE_PATH}" ]; then
            copy_files "${WORKSPACE}/conf/sites-available" "${NGINX_CONF_SITES_AVAILABLE_PATH}"
        fi

        mkdir -vp "${NGINX_CONF_SITES_ENABLED_PATH}"
        local HTTP_SRV_CONFS=("pg_http_connect.conf" \
                              "pg_http_proxy.conf" \
                              "pg_http_tls_cert_import_export_redis.conf" \
                              "pg_http_proxy.conf" \
                              "pg_stream_proxy.conf")
        for HTTP_SRV_CONF in "${HTTP_SRV_CONFS[@]}"; do
            if [ -f "${NGINX_CONF_SITES_AVAILABLE_PATH}/${HTTP_SRV_CONF}" ]; then
                if [ ! -L "${NGINX_CONF_SITES_ENABLED_PATH}/${HTTP_SRV_CONF}" ]; then
                    ln -vs "${NGINX_CONF_SITES_AVAILABLE_PATH}/${HTTP_SRV_CONF}" "${NGINX_CONF_SITES_ENABLED_PATH}/${HTTP_SRV_CONF}"
                fi
            fi
        done

        local EXTRA_CONFS=("cors_params" "pg_redis.conf" "crossdomain.xml")
        for EXTCNF in "${EXTRA_CONFS[@]}"; do
            if [ ! -f "${NGINX_CONF_PATH}/${EXTCNF}" ] || 
                 ! cmp -s "${WORKSPACE}/conf/${EXTCNF}" "${NGINX_CONF_PATH}/${EXTCNF}"; then
                cp -vf ${WORKSPACE}/conf/${EXTCNF} ${NGINX_CONF_PATH}
            fi
        done

        if [ ! -f /etc/ssl/certs/ca-certificates.pem ]; then
            # This is for the lua_ssl_trusted_certificate '/etc/ssl/certs/ca-certificates.pem' setting
            ln -s /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.pem
        fi
    fi
    
    echo
    echo -e "\e[32m> Copy Lua to ${OPENRESTY_PATH}\e[0m"
    # suproxy
    echo
    local PROXY_MODULES=("strmproxy")
    for module in "${PROXY_MODULES[@]}"; do
        if [ "$module" = "strmproxy" ]; then
            find ${WORKSPACE}/lua_src/lua/${module} -type f -name "*.lua" | while read -r file; do
                sed -i 's/"suproxy\./"strmproxy\./g' "$file"
            done
        fi
        mkdir -vp ${NGINX_PATH}/lua/${module}
        copy_files ${WORKSPACE}/lua_src/lua/${module} ${NGINX_PATH}/lua/${module}

        if [ "$module" = "strmproxy" ]; then
            find ${WORKSPACE}/lua_src/lualib/${module} -type f -name "*.lua" | while read -r file; do
                sed -i 's/"suproxy\./"strmproxy\./g' "$file"
            done
        fi
        mkdir -vp ${OPENRESTY_PATH}/lualib/${module}
        copy_files ${WORKSPACE}/lua_src/lualib/${module} ${OPENRESTY_PATH}/lualib/${module}
    done

    install_luarocks_n_packages_for_strmproxy
}

get_openresty_nginx_service_content() {
    local OPENRESTY_SERVICE_FILE_CONTENT="# Stop dance for OpenResty of PacketGo GateWay
# =========================
#
# ExecStop sends SIGSTOP (graceful stop) to OpenResty's nginx process.
# If, after 5s (--retry QUIT/5) nginx is still running, systemd takes control
# and sends SIGTERM (fast shutdown) to the main process.
# After another 5s (TimeoutStopSec=5), and if nginx is alive, systemd sends
# SIGKILL to all the remaining processes in the process group (KillMode=mixed).
#
# nginx signals reference doc:
# http://nginx.org/en/docs/control.html
#
[Unit]
Description=The OpenResty Application Platform for PacketGo GateWay
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=${OPENRESTY_PATH}/nginx/logs/nginx.pid
ExecStartPre=${OPENRESTY_PATH}/nginx/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=${OPENRESTY_PATH}/nginx/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=${OPENRESTY_PATH}/nginx/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile ${OPENRESTY_PATH}/nginx/logs/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
"
    echo "${OPENRESTY_SERVICE_FILE_CONTENT}"
}

create_openresty_nginx_systemd_service() {
    local OPENRESTY_NGINX_SYSTEMD_SERVICE="/usr/lib/systemd/system/openresty.service"
    echo
    echo -e "\e[35m> Create \"$OPENRESTY_NGINX_SYSTEMD_SERVICE\"\e[0m"    
    stop_openresty_nginx

    echo -e "\e[35m> Create an OpenResty Systemd Service \e[0m"
    get_openresty_nginx_service_content | tee ${OPENRESTY_NGINX_SYSTEMD_SERVICE}
    if [ -f "${OPENRESTY_NGINX_SYSTEMD_SERVICE}" ]; then
        ls -l ${OPENRESTY_NGINX_SYSTEMD_SERVICE}
        systemctl enable openresty.service
        systemctl daemon-reload
    fi
}

get_proxy_logrotate_content() {
    local PROXY_LOGROTATE_CONTENT="#
#   Logrotate fragment for openresty nginx.
#
/var/log/openresty/*.log {
    daily
    missingok
    rotate 30
    copytruncate
    compress
    delaycompress
    notifempty
    create 0640 root adm
    dateext
    sharedscripts
    postrotate
        if [ -f \"${OPENRESTY_PATH}/nginx/logs/nginx.pid\" ]; then
            /bin/kill -USR1 \`cat \${OPENRESTY_PATH}/nginx/logs/nginx.pid\`
        fi
    endscript
"
    echo "${PROXY_LOGROTATE_CONTENT}"
}

create_openresty_nginx_logrotate() {
    echo
    echo -e "\e[35m> Create \"/etc/logrotate.d/openresty.logrotate\"\e[0m"
    echo -e "\e[35m> Create an OpenResty logrotate \e[0m"
    get_proxy_logrotate_content | tee /etc/logrotate.d/openresty.logrotate
    ls -l /etc/logrotate.d/openresty.logrotate
}

# Function to create OpenSSL configuration file
# refer to : https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-in-ubuntu-22-04
# The most important line is the one that requests the Common Name (e.g. server FQDN or YOUR name). 
# You need to enter the domain name associated with your server or, more likely, your server’s public IP address.
ROOT_CA_NAME="pg-proxy-rootCA"
create_openssl_root_ca_cnf() {
    if [ $# -ne 1 ]; then
        echo -e "\e[31m> Set the OpenSSL configuration file name.\e[0m"
        return
    fi

    local OPENSSL_CONF="$1"
    if [ -f "${OPENSSL_CONF}" ]; then
        echo -e "\e[31m> \"${OPENSSL_CONF}\" already exists. Skipping generation.\e[0m"
        return
    fi

    local OPENSSL_CONF_CONTENT="[req]
default_bits                   = 2048
default_md                     = sha256
default_keyfile                = ${ROOT_CA_NAME}.key
distinguished_name             = req_distinguished_name
x509_extensions                = v3_ca
req_extensions                 = v3_ca
prompt                         = no

[req_distinguished_name]
countryName                    = KR
stateOrProvinceName            = Seoul
localityName                   = Seoul
organizationName               = PacketGo Service
organizationalUnitName         = Pribit Dev
commonName                     = PacketGo.Proxy.Root.CA

[v3_ca]
basicConstraints               = critical, CA:TRUE
subjectKeyIdentifier           = hash
keyUsage                       = critical, digitalSignature, keyCertSign, cRLSign
extendedKeyUsage               = serverAuth, clientAuth
"

    echo -e "\e[34m> Generate \"${OPENSSL_CONF}\" \e[0m"
    mkdir -p "$(dirname ${OPENSSL_CONF})"
    echo "${OPENSSL_CONF_CONTENT}" | tee "${OPENSSL_CONF}"
}

create_openssl_server_cnf() {
    if [ $# -gt 2 ]; then
        echo -e "\e[31m> Too many arguments. Expected 2 or less.\e[0m"
        return
    fi

    local OPENSSL_CONF="$1"
    if [ -f "${OPENSSL_CONF}" ]; then
        echo -e "\e[31m> \"${OPENSSL_CONF}\" already exists. Skipping generation.\e[0m"
        return
    fi

    local COMMON_NAME="PacketGo.Signed.ServerCA"
    local SERVER_NAME=$2
    if [ -n "${SERVER_NAME}" ]; then
        COMMON_NAME="PacketGo.Signed.${SERVER_NAME}.CA"
    fi

    local OPENSSL_CONF_CONTENT="[req]
default_bits                   = 2048
default_md                     = sha256
default_keyfile                = ${ROOT_CA_NAME}.key
distinguished_name             = req_distinguished_name
x509_extensions                = v3_user
prompt                         = no

[req_distinguished_name]
countryName                    = KR
stateOrProvinceName            = Seoul
localityName                   = Seoul
organizationName               = PacketGo Service
organizationalUnitName         = Pribit Dev
commonName                     = ${COMMON_NAME}
# commonName                    = $(ip a show tun0 | grep -oP 'inet \K[\d.]+')
emailAddress                   = developer@pribit.com

[v3_user]
# Extensions to add to a certificate request
basicConstraints               = CA:FALSE
subjectKeyIdentifier           = hash
authorityKeyIdentifier         = keyid,issuer
keyUsage                       = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign
# Extended Key Usage (EKU) field for SSL
extendedKeyUsage               = serverAuth
subjectAltName                 = @alt_names

[alt_names]
#DNS.1 = localhost
#IP.1 = 127.0.0.1
DNS.1 = PacketGo Root-Signed Certificate
#IP.1 = $(ip a show tun0 | grep -oP 'inet \K[\d.]+')
"

    echo -e "\e[34m> Generate \"${OPENSSL_CONF}\" \e[0m"
    mkdir -p "$(dirname ${OPENSSL_CONF})"
    echo "${OPENSSL_CONF_CONTENT}" | tee "${OPENSSL_CONF}"
}

# Create Self-Signed Certificates
set_certificate_validity_period() {
    local DAYS=3650
    while true; do
        PROMPT_MESSAGE="\e[2;33m> Set the certificate validity period in days (default: $DAYS, maximum: 3650 days):\e[0m "
        read -p "$(echo -e ${PROMPT_MESSAGE}) " PERIOD_DAYS
        PERIOD_DAYS=${PERIOD_DAYS:-$DAYS}
        if [[ "${PERIOD_DAYS}" =~ ^[0-9]+$ ]] && ((PERIOD_DAYS >= 1)) && ((PERIOD_DAYS <= 3650)); then
            DAYS=${PERIOD_DAYS}
            echo "Certificate validity period set to: $DAYS days"
            break
        else
            echo -e "\e[31m> Invalid input. Please input a number within the range of 1 to 3650 days.\e[0m"
        fi
    done
}
create_ssc() {
    echo
    echo -e "\e[1;36m> Current OpenSSL version: $(openssl version) \e[0m"

    local NGINX_CERT_PATH="$NGINX_PATH/certs"
    local NGINX_CERT_CREATE_PATH="$WORKSPACE/certs"

    local ROOT_KEY="$ROOT_CA_NAME.key" # RootCA's Private Key
    local ROOT_CSR="$ROOT_CA_NAME.csr"
    local ROOT_CRT="$ROOT_CA_NAME.crt" # RootCA's Public Key
    local OPENSSL_ROOT_CA_CONF="${NGINX_CERT_CREATE_PATH}/openssl-root.cnf"

    local SERVER_CA_NAME="pg-proxy-signed-server"
    local SERVER_KEY="$SERVER_CA_NAME.key"
    local SERVER_CSR="$SERVER_CA_NAME.csr"
    local SERVER_CRT="$SERVER_CA_NAME.crt"
    local OPENSSL_SERVER_CONF="${NGINX_CERT_CREATE_PATH}/openssl-server.cnf"

    # mTLS (Mutual TLS) Certificate
    local MTLS_CA_NAME="pg-proxy-signed-mtls"
    local MTLS_KEY="$MTLS_CA_NAME.key"
    local MTLS_CSR="$MTLS_CA_NAME.csr"
    local MTLS_CRT="$MTLS_CA_NAME.crt"
    local OPENSSL_MTLS_CONF="${NGINX_CERT_CREATE_PATH}/openssl-mTLS.cnf"

    # for ssh
    local SSH_CA_NAME="pg-rsa-ssh"
    local SSH_RSA_PRI_KEY="${SSH_CA_NAME}.key"
    local SSH_RSA_PUB_KEY="${SSH_CA_NAME}.pub"

    # for ftp
    local FTP_CA_NAME="pg-proxy-signed-ftp"
    local FTP_KEY="${FTP_CA_NAME}.key"
    local FTP_CSR="${FTP_CA_NAME}.csr"
    local FTP_CRT="${FTP_CA_NAME}.crt"
    local OPENSSL_FTP_CONF="${NGINX_CERT_CREATE_PATH}/openssl-ftp.cnf"

    local DHPARAM_PEM="dhparam.pem"

    if [ ! -d "${NGINX_CERT_CREATE_PATH}" ]; then
        mkdir -vp ${NGINX_CERT_CREATE_PATH}
        cd ${NGINX_CERT_CREATE_PATH}
        # rm -vf ${SERVER_CA_NAME}.* ${OPENSSL_SERVER_CONF}

        local VALIDITY_PERIOD=0
    fi

    if [ ! -f "${NGINX_CERT_CREATE_PATH}/${ROOT_CRT}" ]; then
        echo -e "\e[33m> The Root Certificate & Key doesn't exists.\e[0m"
        PROMPT_MESSAGE="\e[33m> Generate Self-Signed Root CA\e[0m (y/N): "
        read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
        USER_RESPONSE=${USER_RESPONSE:-"N"}
        case "$USER_RESPONSE" in
            1|y|Y)
                # Generate Server Self Signed ROOT Certificate & Key
                echo -e "\e[36m> Generate a Self Signed Root Certificate & Key \e[0m"
                echo -e "\e[36m> Create ${ROOT_KEY} \e[0m"
                openssl genrsa -out "${ROOT_KEY}" 2048

                ls -l "${ROOT_KEY}"
                chmod 0600 ${ROOT_KEY}

                echo -e "\e[36m> Create ${ROOT_CSR} \e[0m"
                create_openssl_root_ca_cnf "${OPENSSL_ROOT_CA_CONF}"
                openssl req -new -key "${ROOT_KEY}" -out "${ROOT_CSR}" -config "${OPENSSL_ROOT_CA_CONF}"
                ls -l "${ROOT_CSR}"

                echo -e "\e[36m> Check ${ROOT_CSR} \e[0m"
                openssl req -text -in "${ROOT_CSR}"

                echo -e "\e[36m> Create ${ROOT_CRT} \e[0m"
                if [ "$VALIDITY_PERIOD" -eq 0 ]; then
                    VALIDITY_PERIOD=$(set_certificate_validity_period)
                fi
                echo -e "> VALIDITY_PERIOD: ${VALIDITY_PERIOD}"
                openssl x509 \
                            -req \
                            -sha256 \
                            -days "${VALIDITY_PERIOD}" \
                            -extensions v3_ca \
                            -set_serial 1 \
                            -in "${ROOT_CSR}" \
                            -signkey "${ROOT_KEY}" \
                            -out "${ROOT_CRT}" \
                            -extfile "${OPENSSL_ROOT_CA_CONF}"

                ls -l "${ROOT_CRT}"
                openssl x509 -text -noout -in "${ROOT_CRT}"
                ;;
            *)
                ;;
        esac
    fi

    if [ ! -f "${NGINX_CERT_CREATE_PATH}/${SERVER_CRT}" ]; then
        echo -e "\e[33m> The Server Certificate & Key doesn't exists.\e[0m"
        PROMPT_MESSAGE="\e[33m> Generate a Root CA Signed Server Certificate\e[0m (y/N): "
        read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
        USER_RESPONSE=${USER_RESPONSE:-"N"}
        case "$USER_RESPONSE" in
            1|y|Y)
                # Generate a Server CA-Signed Server Certificate & Key
                echo -e "\e[36m> Generate a RootCA Signed Server Certificate & Key \e[0m"
                echo -e "\e[36m> Create ${SERVER_KEY} \e[0m"
                openssl genrsa -out "${SERVER_KEY}" 2048
                ls -l "${SERVER_KEY}"
                chmod 0600 ${SERVER_KEY}

                echo -e "\e[36m> Create ${SERVER_CSR} \e[0m"
                create_openssl_server_cnf "${OPENSSL_SERVER_CONF}"
                openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -config "${OPENSSL_SERVER_CONF}"
                ls -l "${SERVER_CSR}"
                openssl req -text -in "${SERVER_CSR}"

                echo -e "\e[36m> Create ${SERVER_CRT} \e[0m"
                if [ "$VALIDITY_PERIOD" -eq 0 ]; then
                    VALIDITY_PERIOD=$(set_certificate_validity_period)
                fi
                echo -e "> VALIDITY_PERIOD: ${VALIDITY_PERIOD}"
                openssl x509 \
                            -req \
                            -sha256 \
                            -days "${VALIDITY_PERIOD}" \
                            -extensions v3_user \
                            -in "${SERVER_CSR}" \
                            -CA "${ROOT_CRT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
                            -out "${SERVER_CRT}" \
                            -extfile "${OPENSSL_SERVER_CONF}"

                ls -l ${SERVER_CRT}
                openssl x509 -text -noout -in "${SERVER_CRT}"
                ;;
            *)
                ;;
        esac
    fi

    if [ ! -f "${NGINX_CERT_CREATE_PATH}/${MTLS_CRT}" ]; then
        echo -e "\e[33m> The Server Certificate & Key doesn't exists.\e[0m"
        PROMPT_MESSAGE="\e[33m> Generate a mTLS Certificate\e[0m (y/N): "
        read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
        USER_RESPONSE=${USER_RESPONSE:-"N"}
        case "$USER_RESPONSE" in
            1|y|Y)
                # Generate a Server CA-Signed Server Certificate & Key
                echo -e "\e[36m> Generate a mTLS Certificate & Key \e[0m"
                echo -e "\e[36m> Create ${MTLS_KEY} \e[0m"
                openssl genrsa -out "${MTLS_KEY}" 2048

                echo -e "\e[36m> Create ${MTLS_CSR} \e[0m"
                create_openssl_server_cnf "${OPENSSL_MTLS_CONF}" "mTls"
                openssl req -new -key "${MTLS_KEY}" -out "${MTLS_CSR}" -config "${OPENSSL_MTLS_CONF}"

                echo -e "\e[36m> Create ${MTLS_CRT} \e[0m"
                if [ "$VALIDITY_PERIOD" -eq 0 ]; then
                    VALIDITY_PERIOD=$(set_certificate_validity_period)
                fi
                echo -e "> VALIDITY_PERIOD: ${VALIDITY_PERIOD}"
                openssl x509 \
                            -req \
                            -sha256 \
                            -days "${VALIDITY_PERIOD}" \
                            -extensions v3_user \
                            -in "${MTLS_CSR}" \
                            -CA "${ROOT_CRT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
                            -out "${MTLS_CRT}" \
                            -extfile "${OPENSSL_MTLS_CONF}"

                ls -l "${MTLS_CRT}"
                openssl x509 -text -noout -in "${MTLS_CRT}"
                ;;
            *)
                ;;
        esac
    fi

    if [ ! -f "${NGINX_CERT_CREATE_PATH}/${DHPARAM_PEM}" ]; then
        echo -e "\e[33m> The dhparam.pem doesn't exists.\e[0m"
        PROMPT_MESSAGE="\e[33m> Generate dhparam.pem\e[0m (y/N): "
        read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
        USER_RESPONSE=${USER_RESPONSE:-"N"}
        case "$USER_RESPONSE" in
            1|y|Y)
                # Create a parameter file for the Diffie-Hellman algorithm
                echo -e "\e[36m> Create a parameter file for the Diffie-Hellman algorithm \e[0m"
                openssl dhparam -outform PEM -out "${DHPARAM_PEM}" 2048
                chmod 400 *pem
                ;;
            *)
                ;;
        esac
    fi

    if [ ! -f "${NGINX_CERT_CREATE_PATH}/${SSH_RSA_PRI_KEY}" ]; then
        echo -e "\e[33m> The SSH Key Pair already exists:\e[0m \"$(basename ${NGINX_CERT_CREATE_PATH}/${SSH_RSA_PRI_KEY})\""
        PROMPT_MESSAGE="\e[33m> Generate SSH RSA Key Pair\e[0m (y/N): "
        read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
        case "$USER_RESPONSE" in
            1|y|Y)
                # for dynamic proxy ssh2
                echo -e "\e[36m> Generate a Self Signed SSH Keys \e[0m"
                echo -e "\e[36m> Create ${SSH_RSA_PRI_KEY}/${SSH_RSA_PUB_KEY} \e[0m"
                openssl genrsa -out "${SSH_RSA_PRI_KEY}" 2048

                echo -e "\e[36m> Create ${SSH_RSA_PUB_KEY} \e[0m"
                openssl rsa -in "${SSH_RSA_PRI_KEY}" -RSAPublicKey_out -out "${SSH_RSA_PUB_KEY}"
                ;;
            *)
                ;;
        esac
    fi

    if [ -f "${NGINX_CERT_PATH}/${FTP_KEY}" ]; then
        echo -e "\e[33m> The FTP Key Pair already exists:\e[0m \"$(basename ${NGINX_CERT_CREATE_PATH}/${FTP_KEY})\""
        PROMPT_MESSAGE="\e[33m> Generate FTP Certificate (y/N): \e[0m"
        read -p "$(echo -e $PROMPT_MESSAGE) " USER_RESPONSE
        USER_RESPONSE=${USER_RESPONSE:-"N"}
        case "$USER_RESPONSE" in
            1|y|Y)
                # for dynamic proxy ftp
                echo -e "\e[36m> Generate a Self Signed FTPS SSL/TLS Certificate & Key \e[0m"
                echo -e "\e[36m> Create ${FTP_KEY} \e[0m"
                openssl genrsa -out "${FTP_KEY}" 2048

                echo -e "\e[36m> Create ${FTP_CSR} \e[0m"
                create_openssl_server_cnf "${OPENSSL_FTP_CONF}" "Ftp"
                openssl req -new -key "${FTP_KEY}" -out "${FTP_CSR}" -config "${OPENSSL_FTP_CONF}"

                echo -e "\e[36m> Create ${FTP_CRT} \e[0m"
                if [ "$VALIDITY_PERIOD" -eq 0 ]; then
                    VALIDITY_PERIOD=$(set_certificate_validity_period)
                fi
                echo -e "> VALIDITY_PERIOD: ${VALIDITY_PERIOD}"
                openssl x509 \
                            -req \
                            -sha256 \
                            -days "${VALIDITY_PERIOD}" \
                            -extensions v3_user \
                            -in "${FTP_CSR}" \
                            -CA "${ROOT_CRT}" -CAkey "${ROOT_KEY}" -CAcreateserial \
                            -out "${FTP_CRT}" \
                            -extfile "${OPENSSL_FTP_CONF}"
                ls -l ${FTP_CRT}
                openssl x509 -text -noout -in "${FTP_CRT}"
                ;;
            *)
                ;;
        esac
    fi

    echo
    ls -l .
    mkdir -vp ${NGINX_CERT_PATH}
    if [ -d "${NGINX_CERT_PATH}" ]; then
        copy_files ${NGINX_CERT_CREATE_PATH} ${NGINX_CERT_PATH}
        rm -f ${NGINX_CERT_PATH}/*.csr ${NGINX_CERT_PATH}/*.srl
        chown www-data:www-data ${NGINX_CERT_PATH}/*.key ${NGINX_CERT_PATH}/*.pub ${NGINX_CERT_PATH}/*.crt
        chmod 600 ${NGINX_CERT_PATH}/*.key ${NGINX_CERT_PATH}/*.pub
        chmod 644 ${NGINX_CERT_PATH}/*.
        if ! getfacl "${NGINX_CERT_PATH}" | grep -qw "www-data"; then
            echo -e "\e[32m> Change ownership and permissions of ${NGINX_CERT_PATH} \e[0m"
            echo "> Adding user 'www-data' to the 'root' group."
            setfacl -Rdm u:www-data:rwx,g:www-data:rwx ${NGINX_CERT_PATH}
            setfacl -Rm u:www-data:rwx,g:www-data:rwx ${NGINX_CERT_PATH}
        fi
    fi
}

copy_ssc() {
    echo
    echo -e "\e[33m> Copy Server Certificates & Keys.\e[0m"
    local NGINX_CERT_CREATE_PATH="$WORKSPACE/certs"
    local NGINX_CERT_PATH="$NGINX_PATH/certs"
    if [ -d "${NGINX_CERT_CREATE_PATH}" ]; then
        mkdir -vp ${NGINX_CERT_PATH}
        copy_files ${NGINX_CERT_CREATE_PATH} ${NGINX_CERT_PATH}
        if ! getfacl "${NGINX_CERT_PATH}" | grep -qw "www-data"; then
            echo -e "\e[32m> Change ownership and permissions of ${NGINX_CERT_PATH} \e[0m"
            echo "> Adding user 'www-data' to the 'root' group."
            setfacl -Rdm u:www-data:rwx,g:www-data:rwx ${NGINX_CERT_PATH}
            setfacl -Rm u:www-data:rwx,g:www-data:rwx ${NGINX_CERT_PATH}
        fi
    fi
}

main() {
    echo -e "\e[7m +==============+ \e[0m"
    echo -e "\e[7m | 1. Install   | \e[0m"
    echo -e "\e[7m | 2. Uninstall | \e[0m"
    echo -e "\e[7m +==============+ \e[0m"
    PROMPT_MESSAGE="\e[1m> Number: \e[0m"
    read -p "$(echo -e $PROMPT_MESSAGE)" USER_RESPONSE
    echo -e "\e[1;2m> ------------------------------------------------------------------- \e[0m"
    case "$USER_RESPONSE" in
        1) 
           check_dependencies
           config
           build
           install
           create_openresty_nginx_systemd_service
           create_openresty_nginx_logrotate
           # create_ssc
           copy_ssc
           ;;
        2) uninstall ;;
        *)
            ;;
    esac

    echo
    echo -e "\e[33m> Done. \e[0m"
    echo -e "\e[37m> $(date +%Z\ %Y.%m.%d\ %H:%M:%S) \e[0m"
    echo -e "\e[1;2m> ------------------------------------------------------------------- \e[0m"

    cd ${WORKSPACE}
}

main
