#!/bin/bash
set -e
# ====================================================================================
if [ -z "$UPLOAD_USER" ] || [ -z "$UPLOAD_PASS" ]; then
    echo "Missing UPLOAD_USER or UPLOAD_PASS"
    exit 1
fi
# ====================================================================================
export CFLAGS="-fPIC"
export CXXFLAGS="-fPIC"
export CPPFLAGS="-fPIC"
# ====================================================================================
TOTAL_CORES=$(nproc)
if [[ "$BUILD_CORES" =~ ^[0-9]+$ ]] && [ "$BUILD_CORES" -le 100 ]; then
  CORES=$(( TOTAL_CORES * BUILD_CORES / 100 ))
  [ "$CORES" -lt 1 ] && CORES=1
else
  CORES=${BUILD_CORES:-$TOTAL_CORES}
fi
# ====================================================================================
echo "Updating..." && yum -y update > /dev/null 2>&1; yum -y install dnf-plugins-core > /dev/null 2>&1; dnf -y update > /dev/null 2>&1
echo "Installing base tools..." && dnf install --allowerasing -y epel-release dnf-plugins-core curl jq > /dev/null 2>&1
# ====================================================================================
id raweb &>/dev/null || useradd -M -d /raweb -s /bin/bash raweb; mkdir -p /raweb; chown -R raweb:raweb /raweb; mkdir -p /var/tmp/raweb/body/
# ====================================================================================
LATEST_VERSION_NGINX="$RAWEB_WEBSERVER_VERSION"
RPM_PACKAGE_NAME="raweb-webserver"
RPM_ARCH="x86_64"
RPM_DIST="$BUILD_NAME"
RPM_PACKAGE_FILE_NAME="${RPM_PACKAGE_NAME}-${LATEST_VERSION_NGINX}-${BUILD_CODE}.${RPM_ARCH}.rpm"
RPM_REPO_URL="https://$DOMAIN/$UPLOAD_USER/$BUILD_REPO/${BUILD_CODE}/"
# ====================================================================================
if curl -s "$RPM_REPO_URL" | grep -q "$RPM_PACKAGE_FILE_NAME"; then
    echo "✅ Package $RPM_PACKAGE_FILE_NAME already exists. Skipping build."
    exit 0
fi
# ====================================================================================
echo "Enabling crb..." && dnf config-manager --set-enabled crb > /dev/null 2>&1
echo "Adding remi..." && dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm > /dev/null 2>&1
echo "Enabling remi..." && dnf config-manager --set-enabled remi > /dev/null 2>&1
echo "Clean Repo..." && dnf clean all > /dev/null 2>&1; dnf makecache > /dev/null 2>&1
echo "Installing build tools..." && dnf install --allowerasing -y wget zip unzip gcc gcc-c++ make openssl-devel curl nano git jq \
    libtool pkgconf-pkg-config cmake automake autoconf yajl ssdeep-devel zlib-devel libxslt-devel gd-devel \
    lmdb-libs libmaxminddb libmaxminddb-devel libcurl-devel libxml2 libxml2-devel pcre-devel pcre2-devel c-ares-devel \
    re2-devel rsync GeoIP GeoIP-devel pkg-config diffutils file lua-devel rpm-build > /dev/null 2>&1
# ====================================================================================
GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-/tmp}
NGX_BUILD_PA="/ngx"
mkdir -p $NGX_BUILD_PA/nginx_source
mkdir -p $NGX_BUILD_PA/nginx_mods
# ====================================================================================
cd $NGX_BUILD_PA/nginx_source; echo "Downloading Nginx v${NGINX_VERSION}..." && wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz > /dev/null 2>&1; tar xf nginx-${NGINX_VERSION}.tar.gz && rm -Rf nginx-${NGINX_VERSION}.tar.gz
# ====================================================================================
# BORINGSSL
echo "Downloading BoringSSL v${BORINGSSL_VERSION}..." && cd "$NGX_BUILD_PA/nginx_mods/" && wget https://github.com/google/boringssl/releases/download/$BORINGSSL_VERSION/boringssl-$BORINGSSL_VERSION.tar.gz > /dev/null 2>&1
cd "$NGX_BUILD_PA/nginx_mods/" && tar -xf boringssl-$BORINGSSL_VERSION.tar.gz > /dev/null 2>&1; rm -rf boringssl-$BORINGSSL_VERSION.tar.gz
cd "$NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION"; mkdir -p build; cd build; cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON .. > /dev/null 2>&1; echo "Building BoringSSL..." && make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
mkdir -p "$NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl/lib"
cd "$NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl"; ln -s ../include include
cd "$NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION"; cp "build/libcrypto.a" ".openssl/lib"; cp "build/libssl.a" ".openssl/lib"
# ====================================================================================
# ZLIB
# cd $NGX_BUILD_PA/nginx_mods && echo "Downloading ZLIB..." && wget http://zlib.net/current/zlib.tar.gz > /dev/null 2>&1
# cd $NGX_BUILD_PA/nginx_mods && tar xf zlib.tar.gz; rm -Rf zlib.tar.gz; mv zlib-* zlib
# cd $NGX_BUILD_PA/nginx_mods/zlib && CFLAGS="-fPIC" CXXFLAGS="-fPIC" CPPFLAGS="-fPIC" ./configure > /dev/null 2>&1; make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods && echo "Downloading ZLIB..." && git clone https://github.com/cloudflare/zlib.git > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods/zlib && CFLAGS="-fPIC" CXXFLAGS="-fPIC" CPPFLAGS="-fPIC" ./configure > /dev/null 2>&1; make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
# ====================================================================================
# SYSTEM_PCRE
cd $NGX_BUILD_PA/nginx_mods && echo "Downloading PCRE2..." && wget https://github.com/PCRE2Project/pcre2/archive/refs/tags/pcre2-${SYSTEM_PCRE}.tar.gz > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods && tar xf pcre2-${SYSTEM_PCRE}.tar.gz; rm -Rf pcre2-${SYSTEM_PCRE}.tar.gz
cd $NGX_BUILD_PA/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE} && ./autogen.sh > /dev/null 2>&1; CFLAGS="-fPIC" CXXFLAGS="-fPIC" CPPFLAGS="-fPIC" ./configure --enable-utf --enable-unicode-properties --enable-static > /dev/null 2>&1; echo "Building PCRE2..." && make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
# ====================================================================================
# SYSTEM_MODSECURITY
echo "Downloading ModSecurity..." && cd $NGX_BUILD_PA/nginx_mods && git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity.git > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods/ModSecurity && git submodule init > /dev/null 2>&1 && git submodule update > /dev/null 2>&1 && ./build.sh > /dev/null 2>&1 
cd $NGX_BUILD_PA/nginx_mods/ModSecurity && CFLAGS="-fPIC" CXXFLAGS="-fPIC" CPPFLAGS="-fPIC" ./configure                    \
                                        --prefix=/usr/local/modsecurity       \
                                        CPPFLAGS="-I/usr/local/include -fPIC" \
                                        LDFLAGS="-L/usr/local/lib"            \
                                        CFLAGS="-fPIC"                        \
                                        CXXFLAGS="-fPIC" > /dev/null 2>&1
echo "Compiling ModSecurity..." && make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
# ====================================================================================
# LibInjection
cd $NGX_BUILD_PA/nginx_mods && echo "Downloading LibInjection..." && git clone https://github.com/libinjection/libinjection.git > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods/libinjection && ./autogen.sh > /dev/null 2>&1; CFLAGS="-fPIC" CXXFLAGS="-fPIC" CPPFLAGS="-fPIC" ./configure > /dev/null 2>&1; echo "Building LibInjection..." && make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
# ====================================================================================
# NGX_MOD_MODSECURITY
cd $NGX_BUILD_PA/nginx_mods/; echo "Downloading NgxModSec v${NGX_MOD_MODSECURITY}..." && wget https://github.com/SpiderLabs/ModSecurity-nginx/archive/refs/tags/v${NGX_MOD_MODSECURITY}.tar.gz > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods/; tar xf v${NGX_MOD_MODSECURITY}.tar.gz; rm -Rf v${NGX_MOD_MODSECURITY}.tar.gz
# ====================================================================================
# NGX_MOD_HEADERS_MORE
cd $NGX_BUILD_PA/nginx_mods/; echo "Downloading Headers v${NGX_MOD_HEADERS_MORE}..." && wget https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${NGX_MOD_HEADERS_MORE}.tar.gz > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods/; tar xf v${NGX_MOD_HEADERS_MORE}.tar.gz; rm -Rf v${NGX_MOD_HEADERS_MORE}.tar.gz
# ====================================================================================
# Brotli
cd $NGX_BUILD_PA/nginx_mods/; echo "Downloading Brotli..." && git clone https://github.com/google/ngx_brotli.git > /dev/null 2>&1; cd $NGX_BUILD_PA/nginx_mods/ngx_brotli && git submodule update --init > /dev/null 2>&1
# ====================================================================================
# NGX_MOD_GEOIP2
cd $NGX_BUILD_PA/nginx_mods/; echo "Downloading GEOIP2 v${NGX_MOD_GEOIP2}..." && wget https://github.com/leev/ngx_http_geoip2_module/archive/refs/tags/${NGX_MOD_GEOIP2}.tar.gz > /dev/null 2>&1
cd $NGX_BUILD_PA/nginx_mods/; tar xf ${NGX_MOD_GEOIP2}.tar.gz; rm -Rf ${NGX_MOD_GEOIP2}.tar.gz
# ====================================================================================
# Naxsi
cd $NGX_BUILD_PA/nginx_mods/; echo "Downloading Naxsi..." && git clone --recurse-submodules https://github.com/wargio/naxsi.git naxsi > /dev/null 2>&1
# ====================================================================================
echo "Building Nginx v${NGINX_VERSION}..." && cd $NGX_BUILD_PA/nginx_source/nginx-${NGINX_VERSION} && CFLAGS="-fPIC" CXXFLAGS="-fPIC" CPPFLAGS="-fPIC" ./configure --with-compat \
                                          --user=raweb                                                            \
                                          --group=raweb                                                           \
                                          --build="Raweb Webserver v$NGINX_VERSION"                               \
                                          --sbin-path=/usr/sbin/raweb-webserver                                   \
                                          --conf-path=/raweb/apps/webserver/raweb.conf                            \
                                          --modules-path=/raweb/apps/webserver/modules                            \
                                          --pid-path=/var/run/raweb.pid                                           \
                                          --lock-path=/var/run/raweb.lock                                         \
                                          --error-log-path=/var/log/raweb/webserver_error.log                     \
                                          --http-log-path=/var/log/raweb/webserver_access.log                     \
                                          --http-client-body-temp-path=/var/tmp/raweb/body/client                 \
                                          --http-proxy-temp-path=/var/tmp/raweb/body/proxy                        \
                                          --http-fastcgi-temp-path=/var/tmp/raweb/body/fastcgi                    \
                                          --http-uwsgi-temp-path=/var/tmp/raweb/body/uwsgi                        \
                                          --http-scgi-temp-path=/var/tmp/raweb/body/scgi                          \
                                          --with-openssl=$NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION    \
                                          --with-pcre                                                             \
                                          --with-pcre=$NGX_BUILD_PA/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE}         \
                                          --with-poll_module                                                      \
                                          --with-threads                                                          \
                                          --with-file-aio                                                         \
                                          --with-http_ssl_module                                                  \
                                          --with-http_v2_module                                                   \
                                          --with-http_v3_module                                                   \
                                          --with-http_realip_module                                               \
                                          --with-http_addition_module                                             \
                                          --with-http_xslt_module                                                 \
                                          --with-http_image_filter_module                                         \
                                          --with-http_geoip_module                                                \
                                          --with-http_sub_module                                                  \
                                          --with-http_dav_module                                                  \
                                          --with-http_flv_module                                                  \
                                          --with-http_mp4_module                                                  \
                                          --with-http_gunzip_module                                               \
                                          --with-http_gzip_static_module                                          \
                                          --with-http_auth_request_module                                         \
                                          --with-http_random_index_module                                         \
                                          --with-http_secure_link_module                                          \
                                          --with-http_slice_module                                                \
                                          --with-http_stub_status_module                                          \
                                          --with-mail                                                             \
                                          --with-mail_ssl_module                                                  \
                                          --with-stream                                                           \
                                          --with-stream_ssl_module                                                \
                                          --with-stream_realip_module                                             \
                                          --with-stream_geoip_module                                              \
                                          --with-stream_ssl_preread_module                                        \
                                          --add-module=$NGX_BUILD_PA/nginx_mods/ngx_http_geoip2_module-${NGX_MOD_GEOIP2}          \
                                          --add-module=$NGX_BUILD_PA/nginx_mods/headers-more-nginx-module-${NGX_MOD_HEADERS_MORE} \
                                          --add-module=$NGX_BUILD_PA/nginx_mods/ModSecurity-nginx-${NGX_MOD_MODSECURITY}          \
                                          --add-module=$NGX_BUILD_PA/nginx_mods/naxsi/naxsi_src                                   \
                                          --add-module=$NGX_BUILD_PA/nginx_mods/ngx_brotli                                        \
                                          --with-cc-opt="-O3 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIE -I $NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl/include/ -I /usr/local/modsecurity/include -I $NGX_BUILD_PA/nginx_mods/zlib" \
                                          --with-ld-opt="\
                                              -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie \
                                              -Wl,-rpath,/usr/local/modsecurity/lib \
                                              -L $NGX_BUILD_PA/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE}/.libs \
                                              -L /lib64 \
                                              -L $NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl/lib \
                                              -L $NGX_BUILD_PA/nginx_mods/zlib -lz \
                                              -Wl,--start-group \
                                              -lpcre2-8 \
                                              $NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl/lib/libssl.a \
                                              $NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl/lib/libcrypto.a \
                                              -lbrotlienc -lbrotlicommon \
                                              -Wl,--end-group \
                                              -lstdc++ -lpthread -lcrypt -lm -lxml2 -lxslt -lexslt -lgd -lGeoIP" > /dev/null 2>&1
                                          touch $NGX_BUILD_PA/nginx_mods/boringssl-$BORINGSSL_VERSION/.openssl/include/openssl/ssl.h
                                          make -j$CORES > /dev/null 2>&1; make install; make clean > /dev/null 2>&1
                                          unset NGINX
# ====================================================================================
RPM_BUILD_DIR="$GITHUB_WORKSPACE/rpmbuild"
RPM_ROOT="$RPM_BUILD_DIR/BUILDROOT/${RPM_PACKAGE_NAME}-${LATEST_VERSION_NGINX}.${RPM_ARCH}"
# ====================================================================================
rm -rf "$RPM_BUILD_DIR"
mkdir -p "$RPM_BUILD_DIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$RPM_ROOT/raweb/apps/webserver"
mkdir -p "$RPM_ROOT/etc/systemd/system"
mkdir -p "$RPM_ROOT/usr/lib/"
mkdir -p "$RPM_ROOT/usr/sbin/"
mkdir -p "$RPM_ROOT/var/tmp/raweb/body/"
mkdir -p "$RPM_ROOT/raweb/apps/webserver/modsec/"
mkdir -p "$RPM_ROOT/etc/logrotate.d/"
mkdir -p "$RPM_ROOT/raweb/apps/webserver/config"
mkdir -p "$RPM_ROOT/raweb/apps/webserver/users"
mkdir -p "$RPM_ROOT/raweb/apps/webserver/conf.d"
mkdir -p "$RPM_ROOT/var/log/raweb"
# ====================================================================================
cp /usr/sbin/raweb-webserver "$RPM_ROOT/usr/sbin/"
cp /raweb/apps/webserver/raweb.conf "$RPM_ROOT/raweb/apps/webserver/"
chmod +x "$RPM_ROOT/usr/sbin/raweb-webserver"
# ====================================================================================
for lib in $(ldd /usr/sbin/raweb-webserver | grep "=> /" | awk '{print $3}'); do
    case "$lib" in
        /lib64/libc.so.*|/lib64/ld-linux-x86-64.so.*|/lib64/libm.so.*|/lib64/libpthread.so.*|/lib64/librt.so.*|/lib64/libdl.so.*|/lib64/libgcc_s.so.*|/lib64/libstdc++.so.*)
            # skip system libraries
            ;;
        *)
            cp "$lib" "$RPM_ROOT/usr/lib/"
            ;;
    esac
done
# ====================================================================================
cat > "$RPM_ROOT/etc/systemd/system/raweb-webserver.service" <<EOF
[Unit]
Description=Raweb Webserver
After=network.target
Wants=network.target

[Service]
Type=forking
User=root
WorkingDirectory=/raweb/apps/webserver
ExecStart=/usr/sbin/raweb-webserver -c /raweb/apps/webserver/raweb.conf
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
# ====================================================================================
cat > "$RPM_ROOT/etc/logrotate.d/raweb-webserver" <<EOF
/var/log/raweb/webserver_access.log /var/log/raweb/webserver_error.log {
    size 100M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF
# ====================================================================================
cat > "$RPM_BUILD_DIR/SPECS/${RPM_PACKAGE_NAME}.spec" <<EOF
Name: $RPM_PACKAGE_NAME
Version: $LATEST_VERSION_NGINX
Release: $BUILD_CODE
Summary: Raweb Webserver (nginx) for AlmaLinux $BUILD_CODE
License: BSD
BuildArch: ${RPM_ARCH}
Group: Applications/Internet
Requires: logrotate

%description
Raweb Webserver (nginx) for AlmaLinux $BUILD_CODE.

%post
set -e
id raweb &>/dev/null || useradd -M -d /raweb -s /bin/bash raweb
mkdir -p /raweb/apps/webserver/config/
mkdir -p /raweb/apps/webserver/users/
mkdir -p /raweb/apps/webserver/conf.d/
mkdir -p /raweb/apps/webserver/modsec
mkdir -p /var/log/raweb/
chown -R raweb:raweb /raweb
chown -R raweb:raweb /raweb/*
systemctl daemon-reload
systemctl enable raweb-webserver.service
if ! systemctl is-active --quiet raweb-webserver.service; then
    systemctl start raweb-webserver.service
fi

%preun
if systemctl is-active --quiet raweb-webserver.service; then
    systemctl stop raweb-webserver.service
fi
if systemctl is-enabled --quiet raweb-webserver.service; then
    systemctl disable raweb-webserver.service
fi

%postun
systemctl daemon-reload
rm -f /etc/logrotate.d/raweb-webserver
echo "Raweb Webserver removed successfully"

%files
/usr/sbin/raweb-webserver
/raweb/apps/webserver/raweb.conf
/etc/systemd/system/raweb-webserver.service
/etc/logrotate.d/raweb-webserver
/usr/lib/*
%dir /raweb/apps/webserver
%dir /raweb/apps/webserver/config
%dir /raweb/apps/webserver/users
%dir /raweb/apps/webserver/conf.d
%dir /raweb/apps/webserver/modsec
%dir /var/log/raweb
%dir /var/tmp/raweb/body

%changelog
* $(date "+%a %b %d %Y") Raweb Panel <cd@julio.al> - $LATEST_VERSION_NGINX
- Custom nginx build for Raweb Panel
EOF
# ====================================================================================
echo "%__make         /usr/bin/make -j $CORES" > ~/.rpmmacros
rpmbuild \
  --define "_topdir $RPM_BUILD_DIR" \
  --define "_smp_mflags -j$CORES" \
  --buildroot "$RPM_ROOT" \
  -bb "$RPM_BUILD_DIR/SPECS/${RPM_PACKAGE_NAME}.spec"
RPM_PACKAGE_FILE="$RPM_BUILD_DIR/RPMS/${RPM_ARCH}/${RPM_PACKAGE_NAME}-${LATEST_VERSION_NGINX}-${BUILD_CODE}.${RPM_ARCH}.rpm"
# ====================================================================================
echo "$UPLOAD_PASS" > $GITHUB_WORKSPACE/.rsync
chmod 600 $GITHUB_WORKSPACE/.rsync
rsync -avz --password-file=$GITHUB_WORKSPACE/.rsync "$RPM_PACKAGE_FILE" rsync://$UPLOAD_USER@$DOMAIN/$BUILD_FOLDER/$BUILD_REPO/$BUILD_CODE/