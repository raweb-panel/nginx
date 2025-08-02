#!/bin/bash
set -e
# ====================================================================================
if [ -z "$UPLOAD_USER" ] || [ -z "$UPLOAD_PASS" ]; then
    echo "Missing UPLOAD_USER or UPLOAD_PASS"
    exit 1
fi
# ====================================================================================
TOTAL_CORES=$(nproc)
if [[ "$BUILD_CORES" =~ ^[0-9]+$ ]] && [ "$BUILD_CORES" -le 100 ]; then
  CORES=$(( TOTAL_CORES * BUILD_CORES / 100 ))
  [ "$CORES" -lt 1 ] && CORES=1
else
  CORES=${BUILD_CORES:-$TOTAL_CORES}
fi
# ====================================================================================
export DEBIAN_FRONTEND=noninteractive
echo "Updating..." && apt-get update -y > /dev/null 2>&1; apt-get upgrade -y > /dev/null 2>&1
echo "Installing curl..." && apt-get install curl jq -y > /dev/null 2>&1
id raweb &>/dev/null || useradd -M -d /raweb -s /bin/bash raweb; mkdir -p /raweb; chown -R raweb:raweb /raweb; mkdir -p /var/tmp/raweb/body/
# ====================================================================================
#LATEST_VERSION_NGINX=$(curl -s https://nginx.org/en/download.html | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' | sort -V | tail -1)
LATEST_VERSION_NGINX="$RAWEB_WEBSERVER_VERSION"
DEB_PACKAGE_NAME="raweb-webserver"
DEB_ARCH="amd64"
DEB_DIST="$BUILD_CODE"
DEB_PACKAGE_FILE_NAME="${DEB_PACKAGE_NAME}_${LATEST_VERSION_NGINX}_${DEB_DIST}_${DEB_ARCH}.deb"
DEB_REPO_URL="https://$DOMAIN/$UPLOAD_USER/$BUILD_REPO/${DEB_DIST}/"
# ====================================================================================
if curl -s "$DEB_REPO_URL" | grep -q "$DEB_PACKAGE_FILE_NAME"; then
    echo "✅ Package $DEB_PACKAGE_FILE_NAME already exists. Skipping build."
    exit 0
fi
# ====================================================================================
DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata dialog > /dev/null 2>&1
# apt-get purge nftables firewalld ufw -y; apt-get autoremove -y
echo "Install reqs..." && apt-get -y install wget zip unzip build-essential libssl-dev curl nano git > /dev/null 2>&1
# apt-get -y install iptables ipset
echo "Install reqs..." && apt-get install -y libtool pkg-config make cmake automake autoconf > /dev/null 2>&1
echo "Install reqs..." && apt-get install -y libyajl-dev ssdeep zlib1g-dev libxslt1-dev libgd-dev libgeoip-dev liblmdb-dev libfuzzy-dev libmaxminddb-dev libcurl4-openssl-dev libxml2 libxml2-dev libpcre3-dev mercurial libpcre2-dev libc-ares-dev libre2-dev rsync > /dev/null 2>&1
# ====================================================================================
mkdir -p $NGX_WORK_FOLDER/nginx_source
mkdir -p $NGX_WORK_FOLDER/nginx_mods
# ====================================================================================
if [ ! -d "$NGX_WORK_FOLDER/nginx_source/nginx-${NGINX_VERSION}" ]; then
    cd $NGX_WORK_FOLDER/nginx_source; echo "Downloading Nginx v${NGINX_VERSION}..."; wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz > /dev/null 2>&1; tar xf nginx-${NGINX_VERSION}.tar.gz && rm -Rf nginx-${NGINX_VERSION}.tar.gz
else
    echo "nginx-${NGINX_VERSION} already exists, skipping download."
fi
# ====================================================================================
# BORINGSSL

if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/boringssl" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods; git clone https://boringssl.googlesource.com/boringssl > /dev/null 2>&1
    cd $NGX_WORK_FOLDER/nginx_mods/boringssl; mkdir -p build; cd build; cmake .. > /dev/null 2>&1; echo "Building BoringSSL..." && make -j$CORES > /dev/null 2>&1
    mkdir -p "$NGX_WORK_FOLDER/nginx_mods/boringssl/.openssl/lib"
    cd "$NGX_WORK_FOLDER/nginx_mods/boringssl/.openssl"; ln -s ../include include
    cd "$NGX_WORK_FOLDER/nginx_mods/boringssl"; cp "build/libcrypto.a" ".openssl/lib"; cp "build/libssl.a" ".openssl/lib"
else
    echo "BoringSSL already exists, skipping download."
fi
# ====================================================================================
# ZLIB
# cd $NGX_WORK_FOLDER/nginx_mods && echo "Downloading ZLIB..." && wget http://zlib.net/current/zlib.tar.gz > /dev/null 2>&1
# cd $NGX_WORK_FOLDER/nginx_mods && tar xf zlib.tar.gz; rm -Rf zlib.tar.gz; mv zlib-* zlib
# cd $NGX_WORK_FOLDER/nginx_mods/zlib && CFLAGS=-fPIC CXXFLAGS=-fPIC CPPFLAGS="-fPIC" ./configure > /dev/null 2>&1; make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/zlib" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods && echo "Downloading ZLIB..." && git clone https://github.com/cloudflare/zlib.git > /dev/null 2>&1
    cd $NGX_WORK_FOLDER/nginx_mods/zlib && CFLAGS=-fPIC CXXFLAGS=-fPIC CPPFLAGS="-fPIC" ./configure > /dev/null 2>&1; make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
else
    echo "ZLIB already exists, skipping download."
fi
# ====================================================================================
# SYSTEM_MODSECURITY
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/ModSecurity" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods; echo "Downloading ModSecurity..." && git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity.git > /dev/null 2>&1
    cd $NGX_WORK_FOLDER/nginx_mods/ModSecurity; git submodule init > /dev/null 2>&1; git submodule update > /dev/null 2>&1; ./build.sh > /dev/null 2>&1; ./configure > /dev/null 2>&1; echo "Building ModSecurity..." && make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
else
    echo "ModSecurity already exists, skipping download."
fi
# ====================================================================================
# SYSTEM_PCRE
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE}" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods && echo "Downloading ZLIB..." && wget https://github.com/PCRE2Project/pcre2/archive/refs/tags/pcre2-${SYSTEM_PCRE}.tar.gz > /dev/null 2>&1
    cd $NGX_WORK_FOLDER/nginx_mods && tar xf pcre2-${SYSTEM_PCRE}.tar.gz; rm -Rf pcre2-${SYSTEM_PCRE}.tar.gz
    cd $NGX_WORK_FOLDER/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE} && ./autogen.sh > /dev/null 2>&1; ./configure > /dev/null 2>&1; echo "Building PCRE2..." && make -j$CORES > /dev/null 2>&1
else
    echo "PCRE2 already exists, skipping download."
fi
# ====================================================================================
# LibInjection
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE}" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods && echo "Downloading LibInjection..." && git clone https://github.com/libinjection/libinjection.git > /dev/null 2>&1
    cd $NGX_WORK_FOLDER/nginx_mods/libinjection && ./autogen.sh > /dev/null 2>&1; ./configure > /dev/null 2>&1; echo "Building LibInjection..." && make -j$CORES > /dev/null 2>&1; make install > /dev/null 2>&1
else
    echo "LibInjection already exists, skipping download."
fi
# ====================================================================================
# NGX_MOD_MODSECURITY
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/ModSecurity-nginx-${NGX_MOD_MODSECURITY}" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods/; echo "Downloading NgxModSec v${NGX_MOD_MODSECURITY}..." && wget https://github.com/SpiderLabs/ModSecurity-nginx/archive/refs/tags/v${NGX_MOD_MODSECURITY}.tar.gz > /dev/null 2>&1; tar xf v${NGX_MOD_MODSECURITY}.tar.gz; rm -Rf v${NGX_MOD_MODSECURITY}.tar.gz
else
    echo "ngx_modsecurity already exists, skipping download."
fi
# ====================================================================================
# NGX_MOD_HEADERS_MORE
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/headers-more-nginx-module-${NGX_MOD_HEADERS_MORE}" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods/; echo "Downloading Headers v${NGX_MOD_HEADERS_MORE}..." && wget https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${NGX_MOD_HEADERS_MORE}.tar.gz > /dev/null 2>&1; tar xf v${NGX_MOD_HEADERS_MORE}.tar.gz; rm -Rf v${NGX_MOD_HEADERS_MORE}.tar.gz
else
    echo "ngx_headers_more already exists, skipping download."
fi
# ====================================================================================
# Brotli
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/ngx_brotli" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods/; echo "Downloading Brotli..." && git clone https://github.com/google/ngx_brotli.git > /dev/null 2>&1; cd $NGX_WORK_FOLDER/nginx_mods/ngx_brotli && git submodule update --init > /dev/null 2>&1
else
    echo "ngx_brotli already exists, skipping download."
fi
# ====================================================================================
# NGX_MOD_GEOIP2
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/ngx_http_geoip2_module-${NGX_MOD_GEOIP2}" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods/; echo "Downloading GEOIP2 v${NGX_MOD_GEOIP2}..." && wget https://github.com/leev/ngx_http_geoip2_module/archive/refs/tags/${NGX_MOD_GEOIP2}.tar.gz > /dev/null 2>&1; tar xf ${NGX_MOD_GEOIP2}.tar.gz; rm -Rf ${NGX_MOD_GEOIP2}.tar.gz
else
    echo "ngx_geoip2 already exists, skipping download."
fi
# ====================================================================================
# Naxsi
if [ ! -d "$NGX_WORK_FOLDER/nginx_mods/naxsi/naxsi_src" ]; then
    cd $NGX_WORK_FOLDER/nginx_mods/; echo "Downloading Naxsi..." && git clone --recurse-submodules https://github.com/wargio/naxsi.git naxsi > /dev/null 2>&1
else
    echo "ngx_naxsi already exists, skipping download."
fi
# ====================================================================================
echo "Building Nginx v${NGINX_VERSION}..." && cd $NGX_WORK_FOLDER/nginx_source/nginx-${NGINX_VERSION} && CFLAGS=-fPIC CXXFLAGS=-fPIC ./configure --with-compat \
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
                                          --with-openssl=$NGX_WORK_FOLDER/nginx_mods/boringssl                   \
                                          --with-pcre                                                             \
                                          --with-pcre=$NGX_WORK_FOLDER/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE}     \
                                          --with-zlib=$NGX_WORK_FOLDER/nginx_mods/zlib                           \
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
                                          --add-module=$NGX_WORK_FOLDER/nginx_mods/ngx_http_geoip2_module-${NGX_MOD_GEOIP2}          \
                                          --add-module=$NGX_WORK_FOLDER/nginx_mods/headers-more-nginx-module-${NGX_MOD_HEADERS_MORE} \
                                          --add-module=$NGX_WORK_FOLDER/nginx_mods/ModSecurity-nginx-${NGX_MOD_MODSECURITY}          \
                                          --add-module=$NGX_WORK_FOLDER/nginx_mods/naxsi/naxsi_src                                   \
                                          --add-module=$NGX_WORK_FOLDER/nginx_mods/ngx_brotli                                        \
                                          --with-cc-opt="-O3 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC -I $NGX_WORK_FOLDER/nginx_mods/boringssl/.openssl/include/" \
                                          --with-ld-opt="-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie -L $NGX_WORK_FOLDER/nginx_mods/pcre2-pcre2-${SYSTEM_PCRE}/.libs -lpcre2-8 -L/lib/x86_64-linux-gnu -lpcre -L $NGX_WORK_FOLDER/nginx_mods/boringssl/.openssl/lib/ -lstdc++"
                                          touch $NGX_WORK_FOLDER/nginx_mods/boringssl/.openssl/include/openssl/ssl.h
                                          make -j$CORES; make install; make clean > /dev/null 2>&1
                                          unset NGINX
# ====================================================================================
DEB_BUILD_DIR="$GITHUB_WORKSPACE/debbuild"
DEB_ROOT="$DEB_BUILD_DIR/${DEB_PACKAGE_NAME}_${LATEST_VERSION_NGINX}_${DEB_ARCH}"

rm -rf "$DEB_BUILD_DIR"
mkdir -p "$DEB_ROOT/raweb/apps/webserver"
mkdir -p "$DEB_ROOT/etc/systemd/system"
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/usr/lib/"
mkdir -p "$DEB_ROOT/usr/sbin/"
mdkir -p "$DEB_ROOT/var/tmp/raweb/body/"
mkdir -p "$DEB_ROOT/raweb/apps/webserver/modsec/"
git clone https://github.com/coreruleset/coreruleset.git $DEB_ROOT/raweb/apps/webserver/modsec/owasp-crs

cp /usr/sbin/raweb-webserver "$DEB_ROOT/usr/sbin/"
cp /raweb/apps/webserver/raweb.conf "$DEB_ROOT/raweb/apps/webserver/"
chmod +x "$DEB_ROOT/usr/sbin/raweb-webserver"

cat > "$DEB_ROOT/etc/systemd/system/raweb-webserver.service" <<EOF
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

cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: $DEB_PACKAGE_NAME
Version: $LATEST_VERSION_NGINX
Section: web
Priority: optional
Architecture: $DEB_ARCH
Maintainer: Julio S. <cd@julio.al>
Depends: logrotate, libpcre2-8-0, libssl3, libxml2, libxslt1.1, libgd3, libgeoip1, libmaxminddb0, libcurl4, libc6, zlib1g, libbrotli1, libyajl2, libfuzzy2, liblmdb0, libre2-9, libc-ares2, libmodsecurity3
Description: Raweb Webserver (nginx) for Debian $BUILD_CODE
EOF

cat > "$DEB_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e
id raweb &>/dev/null || useradd -M -d /raweb -s /bin/bash raweb; mkdir -p /raweb; chown -R raweb:raweb /raweb
rm -rf /raweb/apps/webserver/*.default
mkdir -p /raweb/apps/webserver/config/
mkdir -p /raweb/apps/webserver/users/
mkdir -p /raweb/apps/webserver/conf.d/
mkdir -p /raweb/apps/webserver/modsec
mkdir -p /var/log/raweb/
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/config/modules.conf > /raweb/apps/webserver/config/modules.conf
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/config/gzip.conf > /raweb/apps/webserver/config/gzip.conf
if [ ! -f /raweb/apps/webserver/config/banned.conf ]; then
    curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/config/banned.conf > /raweb/apps/webserver/config/banned.conf
fi
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/config/mime.types > /raweb/apps/webserver/config/mime.types
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/raweb.conf > /raweb/apps/webserver/raweb.conf
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/fastcgi.conf > /raweb/apps/webserver/fastcgi.conf
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/fastcgi_params > /raweb/apps/webserver/fastcgi_params
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/koi-utf > /raweb/apps/webserver/koi-utf
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/koi-win > /raweb/apps/webserver/koi-win
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/scgi_params > /raweb/apps/webserver/scgi_params
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/uwsgi_params > /raweb/apps/webserver/uwsgi_params
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/uwsgi_params > /raweb/apps/webserver/uwsgi_params
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/win-utf > /raweb/apps/webserver/win-utf

curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/config/cloudflare.conf > /raweb/apps/webserver/config/cloudflare.conf
curl -s https://raw.githubusercontent.com/raweb-panel/nginx/refs/heads/main/static/config/http_map.conf > /raweb/apps/webserver/config/http_map.conf
curl -s https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules > /raweb/apps/webserver/modsec/naxi.core
curl -s https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended > /raweb/apps/webserver/modsec/modsecurity.conf
echo 'Include /raweb/apps/webserver/modsec/owasp-crs/crs-setup.conf' >> /raweb/apps/webserver/modsec/modsecurity.conf
echo 'Include /raweb/apps/webserver/modsec/owasp-crs/rules/*.conf' >> /raweb/apps/webserver/modsec/modsecurity.conf
curl -s https://raw.githubusercontent.com/theraw/The-World-Is-Yours/master/static/modsec/unicode.mapping > /raweb/apps/webserver/modsec/unicode.mapping
chown -R raweb:raweb /raweb; chown -R raweb:raweb /raweb/*
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable raweb-webserver.service
if ! systemctl is-active --quiet raweb-webserver.service; then
    systemctl start raweb-webserver.service
fi

# Ensure logrotate is installed and reload config
logrotate -f /etc/logrotate.d/raweb-webserver || true

echo "Raweb Webserver installed and started"
EOF

cat > "$DEB_ROOT/DEBIAN/prerm" <<'EOF'
#!/bin/bash
set -e
if systemctl is-active --quiet raweb-webserver.service; then
    systemctl stop raweb-webserver.service
fi
if systemctl is-enabled --quiet raweb-webserver.service; then
    systemctl disable raweb-webserver.service
fi
EOF

cat > "$DEB_ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/bash
set -e
systemctl daemon-reexec
systemctl daemon-reload
if [ -d "/raweb/apps/webserver" ] && [ -z "$(ls -A /raweb/apps/webserver)" ]; then
    rmdir /raweb/apps/webserver
fi
if [ -d "/raweb/apps" ] && [ -z "$(ls -A /raweb/apps)" ]; then
    rmdir /raweb/apps
fi
rm -f /etc/logrotate.d/raweb-webserver
echo "Raweb Webserver removed successfully"
EOF

mkdir -p "$DEB_ROOT/etc/logrotate.d/"
cat > "$DEB_ROOT/etc/logrotate.d/raweb-webserver" <<EOF
/var/log/raweb/webserver_access.log /var/log/raweb/webserver_error.log {
    size 100M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF

chmod 755 "$DEB_ROOT/DEBIAN/postinst" "$DEB_ROOT/DEBIAN/prerm" "$DEB_ROOT/DEBIAN/postrm"

DEB_PACKAGE_FILE="$DEB_BUILD_DIR/${DEB_PACKAGE_NAME}_${LATEST_VERSION_NGINX}_${DEB_DIST}_${DEB_ARCH}.deb"
dpkg-deb --build "$DEB_ROOT" "$DEB_PACKAGE_FILE"

echo "$UPLOAD_PASS" > $GITHUB_WORKSPACE/.rsync
chmod 600 $GITHUB_WORKSPACE/.rsync
rsync -avz --password-file=$GITHUB_WORKSPACE/.rsync "$DEB_PACKAGE_FILE" rsync://$UPLOAD_USER@$DOMAIN/$BUILD_FOLDER/$BUILD_REPO/$BUILD_CODE/
# ====================================================================================
# ====================================================================================
# ====================================================================================