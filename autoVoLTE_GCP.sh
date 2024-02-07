#!/bin/bash

set -a
set -e

HomeDirectory="/home/ash"

source $HomeDirectory/.env
############################################################################################################################################
#sudo apt install espeak
###########################################1. Installation and Configuration of Opne5gs#####################################################
echo -e "\a"
echo "Installation and Configuration of Opne5gs begins ..."
#espeak "Installation and Configuration of Opne5gs begins"

if ! ip link show  ogstun2  &> /dev/null; then
    sudo ip tuntap add name ogstun2 mode tun
    sudo ip addr add 10.46.0.1/16 dev ogstun2
    sudo ip addr add 2001:db8:cafe::1/48 dev ogstun2
    sudo ip link set ogstun2 up
else
    echo "ogstun2 interface already exists"
fi

sudo apt-get install -y gnupg curl 
curl -fsSL https://pgp.mongodb.com/server-6.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

echo "mongodb-org hold" | sudo dpkg --set-selections
echo "mongodb-org-database hold" | sudo dpkg --set-selections
echo "mongodb-org-server hold" | sudo dpkg --set-selections
echo "mongodb-mongosh hold" | sudo dpkg --set-selections
echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
echo "mongodb-org-tools hold" | sudo dpkg --set-selections

sudo systemctl start mongod
sudo systemctl daemon-reload
sudo systemctl enable mongod
#sudo systemctl status mongod

if ! ip link show  ogstun  &> /dev/null; then
    sudo ip tuntap add name ogstun mode tun
    sudo ip addr add 10.45.0.1/16 dev ogstun
    sudo ip addr add 2001:db8:cafe::1/48 dev ogstun
    sudo ip link set ogstun up
else
    echo "ogstun interface already exists"
fi

sudo add-apt-repository ppa:open5gs/latest --y
sudo apt update -y
sudo apt install open5gs -y

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo iptables -t nat -A POSTROUTING -s 10.46.0.0/16 ! -o ogstun2 -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun2 -j MASQUERADE

cd /etc/open5gs/

sudo cat <<EOF > shortcut.sh
sudo systemctl \$1 open5gs-mmed
sudo systemctl \$1 open5gs-sgwcd
sudo systemctl \$1 open5gs-smfd
#sudo systemctl \$1 open5gs-amfd
sudo systemctl \$1 open5gs-sgwud
sudo systemctl \$1 open5gs-upfd
sudo systemctl \$1 open5gs-hssd
sudo systemctl \$1 open5gs-pcrfd
#sudo systemctl \$1 open5gs-nrfd
sudo systemctl \$1 open5gs-scpd
#sudo systemctl \$1 open5gs-ausfd
#sudo systemctl \$1 open5gs-udmd
#sudo systemctl \$1 open5gs-pcfd
#sudo systemctl \$1 open5gs-nssfd
#sudo systemctl \$1 open5gs-bsfd
#sudo systemctl \$1 open5gs-udrd
#sudo systemctl \$1 open5gs-webui
EOF

sudo cat <<EOF > 5gshortcut.sh
sudo systemctl \$1 open5gs-amfd
sudo systemctl \$1 open5gs-nrfd
sudo systemctl \$1 open5gs-ausfd
sudo systemctl \$1 open5gs-udmd
sudo systemctl \$1 open5gs-pcfd
sudo systemctl \$1 open5gs-nssfd
sudo systemctl \$1 open5gs-bsfd
sudo systemctl \$1 open5gs-udrd
EOF

sudo chmod +x shortcut.sh
sudo chmod +x 5gshortcut.sh

sudo bash /etc/open5gs/shortcut.sh restart
#sudo bash /etc/open5gs/shortcut.sh status

cd /etc/open5gs

sudo cp mme.yaml mme.backup

cat <<EOF > mme.yaml
logger:
    file: /var/log/open5gs/mme.log
mme:
    freeDiameter: /etc/freeDiameter/mme.conf
    s1ap:
      - addr: MACHINE_IP
    gtpc:
      - addr: MACHINE_IP
    metrics:
      - addr: MACHINE_IP
        port: 9090
    gummei:
      plmn_id:
        mcc: M_C_C
        mnc: M_N_C
      mme_gid: 2
      mme_code: 1
    tai:
      plmn_id:
        mcc: M_C_C
        mnc: M_N_C
      tac: T_A_C
    security:
        integrity_order : [ EIA2, EIA1, EIA0 ]
        ciphering_order : [ EEA0, EEA1, EEA2 ]
    network_name:
        full: Open5GS
    mme_name: open5gs-mme0
sgwc:
    gtpc:
      - addr: 127.0.0.3
smf:
    gtpc:
      - addr:
        - 127.0.0.4
        - ::1
parameter:

max:

usrsctp:

time:

EOF

sudo cp sgwu.yaml sgwu.backup

cat <<EOF > sgwu.yaml
logger:
    file: /var/log/open5gs/sgwu.log
sgwu:
    pfcp:
      - addr: 127.0.0.6
    gtpu:
      - addr: MACHINE_IP
sgwc:
parameter:
max:
time:
EOF

sudo cp smf.yaml smf.backup

cat <<EOF > smf.yaml
logger:
    file: /var/log/open5gs/smf.log
sbi:
    server:
      no_tls: true
      cacert: /etc/open5gs/tls/ca.crt
      key: /etc/open5gs/tls/smf.key
      cert: /etc/open5gs/tls/smf.crt
    client:
      no_tls: true
      cacert: /etc/open5gs/tls/ca.crt
      key: /etc/open5gs/tls/smf.key
      cert: /etc/open5gs/tls/smf.crt
smf:
   p-cscf:
     - MACHINE_IP
smf:
    sbi:
      - addr: 127.0.0.4
        port: 7777
    pfcp:
      - addr: 127.0.0.4
      - addr: ::1
    gtpc:
      - addr: 127.0.0.4
      - addr: ::1
    gtpu:
      - addr: 127.0.0.4
      - addr: ::1
    metrics:
      - addr: 127.0.0.4
        port: 9090
    subnet:
      - addr: 10.45.0.1/16
        dnn: internet
        dev: ogstun
      - addr: 10.46.0.1/16
        dnn: ims
        dev: ogstun2
    dns:
      - 8.8.8.8
      - 8.8.4.4
      - 2001:4860:4860::8888
      - 2001:4860:4860::8844
    mtu: 1400
    ctf:
      enabled: auto
    freeDiameter: /etc/freeDiameter/smf.conf
scp:
    sbi:
      - addr: 127.0.1.10
        port: 7777
upf:
    pfcp:
      - addr: 127.0.0.7

parameter:
   no_ipv4v6_local_addr_in_packet_filter: true
   
max:

time:
EOF

sudo cp upf.yaml upf.backup

cat <<EOF > upf.yaml
logger:
    file: /var/log/open5gs/upf.log

upf:
    pfcp:
      - addr: 127.0.0.7
    gtpu:
      - addr: 127.0.0.7
    subnet:
      - addr: 10.45.0.1/16
        dnn: internet
        dev: ogstun
      - addr: 10.46.0.1/16
        dnn: ims
        dev: ogstun2
    metrics:
      - addr: 127.0.0.7
        port: 9090

smf:

parameter:

max:

time:
EOF

find /etc/open5gs/ -type f -exec sudo sed -i "s/MACHINE_IP/$MACHINE_IP/g" {} +
find /etc/open5gs/ -type f -exec sudo sed -i "s/M_C_C/$M_C_C/g" {} +
find /etc/open5gs/ -type f -exec sudo sed -i "s/M_N_C/$M_N_C/g" {} +
find /etc/open5gs/ -type f -exec sudo sed -i "s/T_A_C/$T_A_C/g" {} +

cd /etc/open5gs/
bash shortcut.sh restart
bash 5gshortcut.sh stop
bash 5gshortcut.sh disable
bash 5gshortcut.sh mask
#######################################################2. Installlation of Kamailio#########################################################
echo -e "\a"
echo "Installlation of Kamailio begins ..."
#espeak "Installlation of Kamailio begins"

sudo apt-get update && sudo apt-get install -y --no-install-recommends \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        ninja-build \
        build-essential \
        flex \
        bison \
        git \
        cmake \
        libsctp-dev \
        libgnutls28-dev \
        libgcrypt-dev \
        libssl-dev \
        libidn11-dev \
        libmongoc-dev \
        libbson-dev \
        libyaml-dev \
        meson \
        curl \
        gnupg \
        ca-certificates \
        libmicrohttpd-dev \
        libcurl4-gnutls-dev \
        libnghttp2-dev \
        libtins-dev \
        libidn11-dev \
        libtalloc-dev

sudo apt-get update && sudo apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        libssl-dev \
        libyaml-dev \
        libmicrohttpd-dev \
        libmongoc-dev \
        libsctp-dev \
        libcurl4-gnutls-dev \
        libtins-dev \
        libidn11-dev \
        libtalloc-dev \
        netbase \
        ifupdown \
        net-tools \
        iputils-ping \
        python3-setuptools \
        python3-wheel \
        python3-pip \
        iptables \
        iperf && sudo apt-get autoremove -y && sudo apt-get autoclean

sudo su <<EOF
pip3 install click
apt-get update && \
apt-get -y install mysql-server tcpdump screen tmux ntp ntpdate git-core dkms \
gcc flex bison libmysqlclient-dev make libssl-dev libcurl4-openssl-dev \
libxml2-dev libpcre3-dev bash-completion g++ autoconf libmnl-dev \
libsctp-dev libradcli-dev libradcli4 libjson-c-dev pkg-config iproute2 net-tools \
iputils-ping

cd $HomeDirectory

if  [ -d "/usr/local/src/" ]; then
        sudo rm  -r /usr/local/src/
fi

if  [ -d "/usr/local/etc/kamailio" ]; then
        sudo rm  -r /usr/local/etc/kamailio
fi

mkdir -p /usr/local/src/ && cd /usr/local/src/ && git clone https://github.com/herlesupreeth/kamailio && \
       cd kamailio && git checkout 5.3 && cd /usr/local/src/kamailio && make cfg
rm /usr/local/src/kamailio/src/modules.lst

cp $HomeDirectory/modules.lst  /usr/local/src/kamailio/src/

cd /usr/local/src/kamailio && \
	make -j`nproc` Q=0 all | tee make_all.txt && \
        make install | tee make_install.txt && \
        ldconfig
        
sudo echo "SIP_DOMAIN=IMS_DOMAIN_NAME" >> /usr/local/etc/kamailio/kamctlrc
sudo echo "DBENGINE=MYSQL" >> /usr/local/etc/kamailio/kamctlrc

sudo echo "#!define WITH_MYSQL" | cat - /usr/local/etc/kamailio/kamailio.cfg > temp && mv temp /usr/local/etc/kamailio/kamailio.cfg
sudo echo "#!define WITH_AUTH" | cat - /usr/local/etc/kamailio/kamailio.cfg > temp && mv temp /usr/local/etc/kamailio/kamailio.cfg
sudo echo "#!define WITH_USRLOCDB" | cat - /usr/local/etc/kamailio/kamailio.cfg > temp && mv temp /usr/local/etc/kamailio/kamailio.cfg
sudo echo "#!define WITH_NAT" | cat - /usr/local/etc/kamailio/kamailio.cfg > temp && mv temp /usr/local/etc/kamailio/kamailio.cfg
sudo echo "auto_aliases=no" >> /usr/local/etc/kamailio/kamailio.cfg
sudo echo 'alias="IMS_DOMAIN_NAME"' >> /usr/local/etc/kamailio/kamailio.cfg
sudo echo "listen=udp:MACHINE_IP:5060 advertise EXTERNAL_IP:5060" >> /usr/local/etc/kamailio/kamailio.cfg
sudo echo "listen=tcp:MACHINE_IP:5060 advertise EXTERNAL_IP:5060" >> /usr/local/etc/kamailio/kamailio.cfg
EOF

if [ -z "$IMS_DOMAIN_NAME" ] || [ -z "$MACHINE_IP" ]; then
    echo "Error: DOMAIN_NAME or MACHINE_IP is not set."
    exit 1
fi

sudo sed -i "s/IMS_DOMAIN_NAME/$IMS_DOMAIN_NAME/g" /usr/local/etc/kamailio/kamctlrc
sudo sed -i "s/IMS_DOMAIN_NAME/$IMS_DOMAIN_NAME/g" /usr/local/etc/kamailio/kamailio.cfg
sudo sed -i "s/MACHINE_IP/$MACHINE_IP/g" /usr/local/etc/kamailio/kamailio.cfg
sudo sed -i "s/EXTERNAL_IP/$EXTERNAL_IP/g" /usr/local/etc/kamailio/kamailio.cfg

sudo su <<EOF

if mysql -u root -e "use kamailio" 2> /dev/null; then
    echo 'Kamailio database already exists. Skipping the command "kamdbctl create"'
else
    echo "Kamailio database does not exist. Creating..."
    echo -e "\n\utf32\nyes\nyes\nyes" | kamdbctl create
fi

if  [ -f "/etc/init.d/kamailio" ]; then
        sudo rm /etc/init.d/kamailio
fi

cp /usr/local/src/kamailio/pkg/kamailio/deb/bionic/kamailio.init /etc/init.d/kamailio
chmod 755 /etc/init.d/kamailio

sed -i 's|^PATH=/sbin:/bin:/usr/sbin:/usr/bin$|PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin|' /etc/init.d/kamailio
sed -i 's|^DAEMON=/usr/sbin/kamailio$|DAEMON=/usr/local/sbin/kamailio|' /etc/init.d/kamailio
sed -i "\|^CFGFILE=/etc/|c\CFGFILE=/usr/local/etc/kamailio/kamailio.cfg" /etc/init.d/kamailio

if  [ -f "/etc/default/kamailio" ]; then
        sudo rm /etc/default/kamailio
fi

cp /usr/local/src/kamailio/pkg/kamailio/deb/bionic/kamailio.default /etc/default/kamailio
echo "RUN_KAMAILIO=yes" >> /etc/default/kamailio

systemctl daemon-reload

if  [ -d "/var/run/kamailio" ]; then
        sudo rm  -r /var/run/kamailio
fi

mkdir -p /var/run/kamailio

adduser --quiet --system --group --disabled-password \
        --shell /bin/false --gecos "Kamailio" \
        --home /var/run/kamailio kamailio

chown kamailio:kamailio /var/run/kamailio

systemctl start kamailio.service

#systemctl status kamailio.service

EOF

################################################3. Installation and Configuration of RTPProxy##############################################
echo -e "\a"
echo "Installation and Configuration of RTPProxy begins ..."
#espeak "Installation and Configuration of RTPProxy begins"

sudo apt update 
sudo apt install rtpproxy

sudo sed -i "\|^#CONTROL_SOCK=udp|c\CONTROL_SOCK=udp:127.0.0.1:7722" /etc/default/rtpproxy
sudo sed -i 's/EXTRA_OPTS=""/EXTRA_OPTS="-l EXTERNAL_IP -d DBUG:LOG_LOCAL0"/' /etc/default/rtpproxy
sudo sed -i "s/EXTERNAL_IP/$EXTERNAL_IP/g" /etc/default/rtpproxy

sudo systemctl restart rtpproxy
sudo systemctl restart kamailio.service

#sudo systemctl status rtpproxy
#sudo systemctl status kamailio.service

#######################################################4. IMS's Components's Database######################################################
echo -e "\a"
echo "Creating DB for IMS's Components ... "
#espeak "Creating DB for IMS's Components"

sudo mysql << EOF
DROP DATABASE IF EXISTS pcscf;
DROP DATABASE IF EXISTS scscf;
DROP DATABASE IF EXISTS icscf;
CREATE DATABASE pcscf;
CREATE DATABASE scscf;
CREATE DATABASE icscf;
exit
EOF

echo "Press Enter in each case if you have not defined any password"
#espeak "Press Enter in each case if you have not defined any password"

sudo su << EOF
cd /usr/local/src/kamailio/utils/kamctl/mysql

mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root pcscf < standard-create.sql 
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root pcscf < presence-create.sql
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root pcscf < ims_usrloc_pcscf-create.sql
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root pcscf < ims_dialog-create.sql

mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root scscf < standard-create.sql
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root scscf < presence-create.sql
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root scscf < ims_usrloc_scscf-create.sql
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root scscf < ims_dialog-create.sql
mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root scscf < ims_charging-create.sql

cd /usr/local/src/kamailio/misc/examples/ims/icscf

mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root icscf < icscf.sql

EOF

sudo mysql -u root << EOF
USE mysql;
UPDATE user SET plugin='mysql_native_password' WHERE User='root';
FLUSH PRIVILEGES;
EOF

sudo mysql -u root -h 127.0.0.1 << EOF

DROP USER IF EXISTS 'pcscf'@'%';
DROP USER IF EXISTS 'pcscf'@'localhost';
FLUSH PRIVILEGES;
CREATE USER 'pcscf'@'%' IDENTIFIED WITH mysql_native_password BY 'heslo';
CREATE USER 'pcscf'@'localhost' IDENTIFIED WITH mysql_native_password BY 'heslo';
GRANT ALL ON pcscf.* TO 'pcscf'@'%';
GRANT ALL ON pcscf.* TO 'pcscf'@'localhost';
FLUSH PRIVILEGES;

DROP USER IF EXISTS 'scscf'@'%';
DROP USER IF EXISTS 'scscf'@'localhost';
FLUSH PRIVILEGES;
CREATE USER 'scscf'@'%' IDENTIFIED WITH mysql_native_password BY 'heslo';
CREATE USER 'scscf'@'localhost' IDENTIFIED WITH mysql_native_password BY 'heslo';
GRANT ALL ON scscf.* TO 'scscf'@'%';
GRANT ALL ON scscf.* TO 'scscf'@'localhost';
FLUSH PRIVILEGES;

DROP USER IF EXISTS 'icscf'@'%';
DROP USER IF EXISTS 'icscf'@'localhost';
FLUSH PRIVILEGES;
CREATE USER 'icscf'@'%' IDENTIFIED WITH mysql_native_password BY 'heslo';
CREATE USER 'icscf'@'localhost' IDENTIFIED WITH mysql_native_password BY 'heslo';
GRANT ALL ON icscf.* TO 'icscf'@'%';
GRANT ALL ON icscf.* TO 'icscf'@'localhost';
FLUSH PRIVILEGES;

DROP USER IF EXISTS 'provisioning'@'%';
DROP USER IF EXISTS 'provisioning'@'localhost';
FLUSH PRIVILEGES;
CREATE USER 'provisioning'@'%' IDENTIFIED WITH mysql_native_password BY 'provi';
CREATE USER 'provisioning'@'localhost' IDENTIFIED WITH mysql_native_password BY 'provi';
GRANT ALL ON icscf.* TO 'provisioning'@'%';
GRANT ALL ON icscf.* TO 'provisioning'@'localhost';
FLUSH PRIVILEGES;

EOF

sudo mysql  << EOF

use icscf;

INSERT INTO \`nds_trusted_domains\` VALUES (1,'$IMS_DOMAIN_NAME');
INSERT INTO \`s_cscf\` VALUES (1,'First and only S-CSCF','sip:scscf.$IMS_DOMAIN_NAME:6060');
INSERT INTO \`s_cscf_capabilities\` VALUES (1,1,0),(2,1,1);

EOF

######################################################5. Fetching IMS's Components##########################################################
echo -e "\a"
echo "Fetching IMS's Components ... "
#espeak "Fetching IMS's Components"

cd $HomeDirectory

if  [ -d "$HomeDirectory/Kamailio_IMS_Config" ]; then
        sudo rm  -r $HomeDirectory/Kamailio_IMS_Config
fi

git clone https://github.com/herlesupreeth/Kamailio_IMS_Config
cd Kamailio_IMS_Config

if  [ -d "/etc/kamailio_pcscf" ]; then
        sudo rm  -r /etc/kamailio_pcscf
fi
if  [ -d "/etc/kamailio_scscf" ]; then
        sudo rm  -r /etc/kamailio_scscf
fi
if  [ -d "/etc/kamailio_icscf" ]; then
        sudo rm  -r /etc/kamailio_icscf
fi

sudo cp -r kamailio_icscf /etc
sudo cp -r kamailio_pcscf /etc
sudo cp -r kamailio_scscf /etc

sudo find /etc/kamailio_*/ -type f -exec sed -i "s/10.4.128.21/MACHINE_IP/g"  {} +
sudo find /etc/kamailio_*/ -type f -exec sed -i "s/ims.mnc001.mcc001.3gppnetwork.org/IMS_DOMAIN_NAME/g" {} +
sudo find /etc/kamailio_*/ -type f -exec sed -i "s/epc.mnc001.mcc001.3gppnetwork.org/EPC_DOMAIN_NAME/g" {} +

sudo find /etc/kamailio_*/ -type f -exec sed -i "s/MACHINE_IP/$MACHINE_IP/g"  {} +
sudo find /etc/kamailio_*/ -type f -exec sed -i "s/IMS_DOMAIN_NAME/$IMS_DOMAIN_NAME/g" {} +
sudo find /etc/kamailio_*/ -type f -exec sed -i "s/EPC_DOMAIN_NAME/$EPC_DOMAIN_NAME/g" {} +

###############################################################6. DNS BIND##################################################################
echo -e "\a"
echo "DNS Binding begins ..."
#espeak "DNS Binding begins"

sudo apt-get update
sudo apt-get -y install tcpdump screen tmux ntp ntpdate iproute2 net-tools iputils-ping bind9

cd /etc/bind/

if  [ -f "/etc/bind/$IMS_DOMAIN_NAME" ]; then
        sudo rm /etc/bind/$IMS_DOMAIN_NAME
fi

cat <<EOF > $IMS_DOMAIN_NAME
\$ORIGIN $IMS_DOMAIN_NAME.
\$TTL 1W
@                       1D IN SOA       localhost. root.localhost. (
                                        1               ; serial
                                        3H              ; refresh
                                        15M             ; retry
                                        1W              ; expiry
                                        1D )            ; minimum

                        1D IN NS        ns
ns                      1D IN A         MACHINE_IP

pcscf                   1D IN A         MACHINE_IP
_sip._udp.pcscf         1D SRV 0 0 5060 pcscf
_sip._tcp.pcscf         1D SRV 0 0 5060 pcscf

icscf                   1D IN A         MACHINE_IP
_sip._udp               1D SRV 0 0 4060 icscf
_sip._tcp               1D SRV 0 0 4060 icscf

scscf                   1D IN A         MACHINE_IP
_sip._udp.scscf         1D SRV 0 0 6060 scscf
_sip._tcp.scscf         1D SRV 0 0 6060 scscf

hss                     1D IN A         MACHINE_IP

EOF

if  [ -f "/etc/bind/$EPC_DOMAIN_NAME" ]; then
        sudo rm /etc/bind/$EPC_DOMAIN_NAME
fi

cat <<EOF > $EPC_DOMAIN_NAME
\$ORIGIN $EPC_DOMAIN_NAME.
\$TTL 1W
@                       1D IN SOA       localhost. root.localhost. (
                                        1               ; serial
                                        3H              ; refresh
                                        15M             ; retry
                                        1W              ; expiry
                                        1D )            ; minimum

                        1D IN NS        epcns
epcns                   1D IN A         MACHINE_IP

pcrf                    1D IN A         127.0.0.9

EOF

sudo find /etc/bind/ -type f -exec sed -i "s/MACHINE_IP/$MACHINE_IP/g" {} +

if  [ -f "/etc/bind/named.conf.local.backup" ]; then
        sudo mv /etc/bind/named.conf.local.backup /etc/bind/named.conf.local
fi

sudo cp /etc/bind/named.conf.local /etc/bind/named.conf.local.backup

echo "zone \"$IMS_DOMAIN_NAME\" {
        type master;
        file \"/etc/bind/$IMS_DOMAIN_NAME\";
};" >> /etc/bind/named.conf.local

echo "zone \"$EPC_DOMAIN_NAME\" {
        type master;
        file \"/etc/bind/$EPC_DOMAIN_NAME\";
};" >> /etc/bind/named.conf.local

sudo rm /etc/bind/named.conf.options
cd /etc/bind/

cat <<EOF >named.conf.options
options {
        directory "/var/cache/bind";
	dnssec-validation no;
        allow-query { any; };
        auth-nxdomain no;
};
EOF

if  [ -f "/etc/resolv.backup" ]; then
        sudo mv /etc/resolv.backup /etc/resolv.conf
fi

#sudo cp /etc/resolv.conf /etc/resolv.backup
#sudo echo "search $IMS_DOMAIN_NAME" | cat - /etc/resolv.conf  > temp && mv temp /etc/resolv.conf 
#sudo echo "nameserver $MACHINE_IP" | cat - /etc/resolv.conf  > temp && mv temp /etc/resolv.conf

sudo systemctl restart bind9

##############################################7. RTPEngine Installation & Configuration#####################################################
{
set +e
echo -e "\a"
echo "RTPEngine Installation begins ..."
#espeak "RTPEngine Installation begins"

cd $HomeDirectory

if  [ -d "$HomeDirectory/rtpengine" ]; then
        sudo rm  -r HomeDirectory/rtpengine
fi

sudo su << EOF
export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_PROFILES="pkg.ngcp-rtpengine.nobcg729"

apt-get update
apt-get -y install git vim tmux dpkg-dev debhelper libxtables-dev default-libmysqlclient-dev gperf libavcodec-dev libavfilter-dev libavformat-dev 
apt-get -y install libavutil-dev libbencode-perl libcrypt-openssl-rsa-perl libcrypt-rijndael-perl libdigest-crc-perl libdigest-hmac-perl 
apt-get -y install libevent-dev libhiredis-dev libio-multiplex-perl libio-socket-inet6-perl libiptc-dev libjson-glib-dev libnet-interface-perl 
apt-get -y install libpcap0.8-dev libpcre3-dev libsocket6-perl libspandsp-dev libssl-dev libswresample-dev libsystemd-dev libxmlrpc-core-c3-dev 
apt-get -y install markdown dkms module-assistant keyutils libnfsidmap2 nfs-common rpcbind libglib2.0-dev zlib1g-dev libavcodec-extra 
apt-get -y install libcurl4-openssl-dev netcat-openbsd netcat iptables iproute2 net-tools iputils-ping libconfig-tiny-perl libwebsockets-dev

export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_PROFILES="pkg.ngcp-rtpengine.nobcg729"

PromptToContinue() {
	read -p "An error occurred. Press Enter to continue ..." input
}
git clone https://github.com/sipwise/rtpengine && \
     cd rtpengine && git checkout mr9.4.1 && dpkg-checkbuilddeps && \
     dpkg-buildpackage -b -uc -us && cd .. \
     && dpkg -i *.deb && ldconfig || PromptToContinue

EOF

sudo cp /etc/rtpengine/rtpengine.sample.conf /etc/rtpengine/rtpengine.conf

sudo sed -i "2s/.*/interface = $MACHINE_IP/" /etc/rtpengine/rtpengine.conf

sudo sed -i "s/RUN_RTPENGINE=no/RUN_RTPENGINE=yes/" /etc/default/ngcp-rtpengine-daemon

sudo sed -i "s/RUN_RTPENGINE_RECORDING=no/RUN_RTPENGINE_RECORDING=yes/" /etc/default/ngcp-rtpengine-recording-daemon

sudo cp /etc/rtpengine/rtpengine-recording.sample.conf /etc/rtpengine/rtpengine-recording.conf

if  [ -d "/var/spool/rtpengine/" ]; then
        sudo rm  -r /var/spool/rtpengine/
fi

sudo mkdir /var/spool/rtpengine

sudo systemctl restart ngcp-rtpengine-daemon.service ngcp-rtpengine-recording-daemon.service ngcp-rtpengine-recording-nfs-mount.service
sudo systemctl enable ngcp-rtpengine-daemon.service ngcp-rtpengine-recording-daemon.service ngcp-rtpengine-recording-nfs-mount.service
#sudo systemctl status ngcp-rtpengine-daemon.service ngcp-rtpengine-recording-daemon.service ngcp-rtpengine-recording-nfs-mount.service
}
#################################################Preapartion for Running IMS Components####################################################

#################################################Configure Open5gs
echo -e "\a"
echo "Configuration of Open5gs for IMS's Components begins ... "
#espeak "Configuration of Open5gs for IMS's Components begins"

sudo rm /etc/freeDiameter/hss.conf

hss_conf='
Identity = "hss.EPC_DOMAIN_NAME";
Realm = "EPC_DOMAIN_NAME";
ListenOn = "127.0.0.8";
TLS_Cred = "/etc/open5gs/tls/hss.crt", "/etc/open5gs/tls/hss.key";
TLS_CA = "/etc/open5gs/tls/ca.crt";
NoRelay;
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dbg_msg_dumps.fdx" : "0x8888";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_rfc5777.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_mip6i.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nasreq.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nas_mipv6.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca_3gpp.fdx";
ConnectPeer = "mme.EPC_DOMAIN_NAME" { ConnectTo = "127.0.0.2"; No_TLS; };
'
echo "$hss_conf" > /etc/freeDiameter/hss.conf

sudo rm /etc/freeDiameter/mme.conf

mme_conf='
Identity = "mme.EPC_DOMAIN_NAME";
Realm = "EPC_DOMAIN_NAME";
ListenOn = "127.0.0.2";
TLS_Cred = "/etc/open5gs/tls/mme.crt", "/etc/open5gs/tls/mme.key";
TLS_CA = "/etc/open5gs/tls/ca.crt";
NoRelay;
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dbg_msg_dumps.fdx" : "0x8888";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_rfc5777.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_mip6i.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nasreq.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nas_mipv6.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca_3gpp.fdx";
ConnectPeer = "hss.EPC_DOMAIN_NAME" { ConnectTo = "127.0.0.8"; No_TLS; };
'
echo "$mme_conf" > /etc/freeDiameter/mme.conf

sudo rm /etc/freeDiameter/smf.conf

smf_conf='
Identity = "smf.EPC_DOMAIN_NAME";
Realm = "EPC_DOMAIN_NAME";
ListenOn = "127.0.0.4";
TLS_Cred = "/etc/open5gs/tls/smf.crt", "/etc/open5gs/tls/smf.key";
TLS_CA = "/etc/open5gs/tls/ca.crt";
NoRelay;
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dbg_msg_dumps.fdx" : "0x8888";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_rfc5777.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_mip6i.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nasreq.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nas_mipv6.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca_3gpp.fdx";
ConnectPeer = "pcrf.EPC_DOMAIN_NAME" { ConnectTo = "127.0.0.9"; No_TLS; };
'
echo "$smf_conf" > /etc/freeDiameter/smf.conf

sudo rm /etc/freeDiameter/pcrf.conf

pcrf_conf='
Identity = "pcrf.EPC_DOMAIN_NAME";
Realm = "EPC_DOMAIN_NAME";
ListenOn = "127.0.0.9";
TLS_Cred = "/etc/open5gs/tls/pcrf.crt", "/etc/open5gs/tls/pcrf.key";
TLS_CA = "/etc/open5gs/tls/ca.crt";
NoRelay;
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dbg_msg_dumps.fdx" : "0x8888";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_rfc5777.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_mip6i.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nasreq.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_nas_mipv6.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca.fdx";
LoadExtension = "/usr/lib/x86_64-linux-gnu/freeDiameter/dict_dcca_3gpp.fdx";
ConnectPeer = "smf.EPC_DOMAIN_NAME" { ConnectTo = "127.0.0.4"; No_TLS; };
ConnectPeer = "pcscf.IMS_DOMAIN_NAME" { ConnectTo = "MACHINE_IP"; No_TLS;Port = 3871; };
'
echo "$pcrf_conf" > /etc/freeDiameter/pcrf.conf
sudo sed -i "s/MACHINE_IP/$MACHINE_IP/" /etc/freeDiameter/pcrf.conf

find /etc/freeDiameter/ -type f -exec sudo sed -i "s/MACHINE_IP/$MACHINE_IP/g" {} +
find /etc/freeDiameter/ -type f -exec sudo sed -i "s/IMS_DOMAIN_NAME/$IMS_DOMAIN_NAME/g" {} +
find /etc/freeDiameter/ -type f -exec sudo sed -i "s/EPC_DOMAIN_NAME/$EPC_DOMAIN_NAME/g" {} +

###################################################Create TLS Certificates and Keys
echo -e "\a"
echo "Create TLS Certificates and Keys"
#espeak "Create TLS Certificates and Keys"

sudo rm /etc/open5gs/tls/*

openssl req -new -x509 -days 3650 -newkey rsa:2048 -nodes -keyout /etc/open5gs/tls/ca.key -out /etc/open5gs/tls/ca.crt     -subj "/CN=ca.$EPC_DOMAIN_NAME/C=KO/ST=Seoul/O=NeoPlane"

create_cert='
#!/bin/sh

if [ 1 -ne $# ]
then
    echo You must specify output directory : ./make-certs.sh ../config/open5gs/tls
    exit;
fi

rm -rf demoCA
mkdir demoCA
echo 01 > demoCA/serial
touch demoCA/index.txt

for i in amf ausf bsf hss mme nrf nssf pcf pcrf scp smf udm udr
do
    openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 \
        -out $1/$i.key
    openssl req -new -key $1/$i.key -out $1/$i.csr \
        -subj /CN=$i.EPC_DOMAIN_NAME/C=KO/ST=Seoul/O=NeoPlane
    openssl ca -batch -notext -days 3650 \
        -keyfile $1/ca.key -cert $1/ca.crt \
        -in $1/$i.csr -out $1/$i.crt -outdir .
done

rm -rf demoCA
rm -f /etc/open5gs/tls/*.pem
rm -f /etc/open5gs/tls/*.csr
rm -f /etc/open5gs/tls/ca.key
'
echo "$create_cert" > /etc/open5gs/tls/createCERT.sh
sudo sed -i "s/EPC_DOMAIN_NAME/$EPC_DOMAIN_NAME/g" /etc/open5gs/tls/createCERT.sh

sudo chmod 777 /etc/open5gs/tls/createCERT.sh
cd /etc/open5gs/tls/
sudo ./createCERT.sh /etc/open5gs/tls/
sudo chmod 777 /etc/open5gs/tls/*

bash /etc/open5gs/shortcut.sh restart

###############################################
echo -e "\a"
echo "Installation and Configuration of FHoSS begins ..."
#espeak "Installation and Configuration of FHoSS begins"

if  [ -d "/usr/bin/java" ]; then
        sudo rm -r /usr/bin/java
fi

if  [ -d "/usr/bin/java" ]; then
        sudo rm -r /usr/bin/javac
fi

cd $HomeDirectory

if  [ -f "$HomeDirectory/jdk-7u79-linux-x64.tar.gz" ]; then
        sudo rm $HomeDirectory/jdk-7u79-linux-x64.tar.gz
fi

wget https://packages.baidu.com/app/jdk-7/jdk-7u79-linux-x64.tar.gz

if  [ -d "/usr/lib/jvm/" ]; then
        sudo rm -r /usr/lib/jvm/
fi

sudo mkdir -p  /usr/lib/jvm/
sudo tar -zxf jdk-7u79-linux-x64.tar.gz -C /usr/lib/jvm/
sudo update-alternatives --install /usr/bin/java java /usr/lib/jvm/jdk1.7.0_79/bin/java 100
sudo update-alternatives --install /usr/bin/javac javac /usr/lib/jvm/jdk1.7.0_79/bin/javac 100
sudo update-alternatives --display java
sudo update-alternatives --display javac
sudo update-alternatives --config java
sudo update-alternatives --config javac
#java -version

cd $HomeDirectory

if  [ -f "$HomeDirectory/apache-ant-1.9.14-bin.tar.gz" ]; then
        sudo rm HomeDirectory/apache-ant-1.9.14-bin.tar.gz
fi
if  [ -f "$HomeDirectory/apache-ant-1.9.14" ]; then
        sudo rm HomeDirectory/apache-ant-1.9.14
fi
if  [ -d "/usr/local/apache-ant-1.9.14/" ]; then
        sudo rm -r /usr/local/apache-ant-1.9.14/           
fi
if  [ -d "/usr/bin/ant" ]; then
        sudo rm -r /usr/bin/ant           
fi

wget http://archive.apache.org/dist/ant/binaries/apache-ant-1.9.14-bin.tar.gz
sudo tar xvfvz apache-ant-1.9.14-bin.tar.gz
sudo mv apache-ant-1.9.14 /usr/local/
sudo sh -c 'echo ANT_HOME=/usr/local/  >> /etc/environment'
sudo ln -s /usr/local/apache-ant-1.9.14/bin/ant /usr/bin/ant
#ant -version

if  [ -d "/opt/OpenIMSCore" ]; then
        sudo rm -r /opt/OpenIMSCore           
fi

sudo mkdir /opt/OpenIMSCore
cd /opt/OpenIMSCore

sudo git clone https://github.com/herlesupreeth/FHoSS 

cd /opt/OpenIMSCore/FHoSS

sudo su <<EOF
export JAVA_HOME="/usr/lib/jvm/jdk1.7.0_79"
export CLASSPATH="/usr/lib/jvm/jdk1.7.0_79/jre/lib/"
export ANT_HOME="/usr/local/apache-ant-1.9.14"
sh -c 'echo ANT_HOME=/usr/local/  >> /etc/environment'
ant compile deploy | tee ant_compile_deploy.txt
EOF

cd /opt/OpenIMSCore/FHoSS/deploy

configurator_content='#!/bin/bash
# Initialization & global vars
# if you execute this script for the second time
# you should change these variables to the latest
# domain name and ip address
DDOMAIN="open-ims\.test"
DSDOMAIN="open-ims\\\.test"
DEFAULTIP="127\.0\.0\.1"
CONFFILES=`ls *.cfg *.xml *.sql *.properties 2>/dev/null`

# Interaction
source /home/ash/.env
echo $MACHINE_IP
echo $IMS_DOMAIN_NAME

# input domain is to be slashed for cfg regexes 
slasheddomain=`echo $IMS_DOMAIN_NAME | sed "s/\./\\\\\\\\\./g"`

if [ $# != 0 ] 
then 
    printf "changing: "
    for j in $* 
    do
        sed -i -e "s/$DDOMAIN/$IMS_DOMAIN_NAME/g" $j
        sed -i -e "s/$DSDOMAIN/$slasheddomain/g" $j
        sed -i -e "s/$DEFAULTIP/$MACHINE_IP/g" $j
        printf "$j " 
    done
    echo 
else 
filename="all"
printf "changing: "
for i in $CONFFILES 
    do
                sed -i -e "s/$DDOMAIN/$IMS_DOMAIN_NAME/g" $i
                sed -i -e "s/$DSDOMAIN/$slasheddomain/g" $i
                sed -i -e "s/$DEFAULTIP/$MACHINE_IP/g" $i
                printf "$i " 
    done  
    echo
fi
'
echo "$configurator_content" > configurator.sh

sudo chmod +x configurator.sh
sudo ./configurator.sh

sudo sed -i "s|<realm-name>open-ims.org</realm-name>|<realm-name>DOMAIN_NAME</realm-name>|" /opt/OpenIMSCore/FHoSS/deploy/webapps/hss.web.console/WEB-INF/web.xml
sudo sed -i "s|DOMAIN_NAME|$IMS_DOMAIN_NAME|" /opt/OpenIMSCore/FHoSS/deploy/webapps/hss.web.console/WEB-INF/web.xml
sudo sed -i "\|^hibernate.connection.url|c\hibernate.connection.url=jdbc:mysql://127.0.0.1:3306/hss_db" /opt/OpenIMSCore/FHoSS/deploy/hibernate.properties
sudo sed -i "s|<realm-name>open-ims.org</realm-name>|<realm-name>DOMAIN_NAME</realm-name>|" /opt/OpenIMSCore/FHoSS/src-web/WEB-INF/web.xml
sudo sed -i "s|DOMAIN_NAME|$IMS_DOMAIN_NAME|" /opt/OpenIMSCore/FHoSS/src-web/WEB-INF/web.xml

sudo cp /opt/OpenIMSCore/FHoSS/deploy/configurator.sh /opt/OpenIMSCore/FHoSS/scripts/
sudo cp /opt/OpenIMSCore/FHoSS/deploy/configurator.sh /opt/OpenIMSCore/FHoSS/config/

cd /opt/OpenIMSCore/FHoSS/scripts/
sudo ./configurator.sh
cd /opt/OpenIMSCore/FHoSS/config/
sudo ./configurator.sh

sed -i "s|grant delete,insert,select,update on hss_db.* to hss@localhost identified by 'hss';|#grant delete,insert,select,update on hss_db.* to hss@localhost identified by 'hss';|" /opt/OpenIMSCore/FHoSS/scripts/hss_db.sql

sudo mysql << EOF 
drop database IF EXISTS hss_db;
create database hss_db;
exit
EOF

cd /opt/OpenIMSCore
sudo mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root hss_db < FHoSS/scripts/hss_db.sql
sudo mysql --defaults-extra-file=$HomeDirectory/mysql.cnf -u root hss_db < FHoSS/scripts/userdata.sql

sudo mysql -u root << EOF
USE mysql;
UPDATE user SET plugin='mysql_native_password' WHERE User='root';
FLUSH PRIVILEGES;
EOF

sudo mysql -u root -h 127.0.0.1 << EOF
DROP USER IF EXISTS 'hss'@'%';
DROP USER IF EXISTS 'hss'@'localhost';
CREATE USER 'hss'@'%' IDENTIFIED WITH mysql_native_password BY 'hss';
CREATE USER 'hss'@'localhost' IDENTIFIED WITH mysql_native_password BY 'hss';
GRANT ALL ON hss_db.* TO 'hss'@'%';
GRANT ALL ON hss_db.* TO 'hss'@'localhost';
FLUSH PRIVILEGES;
EOF

if  [ -f "/root/hss.sh" ]; then
        sudo rm /root/hss.sh
fi

sudo cp /opt/OpenIMSCore/FHoSS/deploy/startup.sh /root/hss.sh

ContentToAdd="cd /opt/OpenIMSCore/FHoSS/deploy\nJAVA_HOME="/usr/lib/jvm/jdk1.7.0_79"\nCLASSPATH="/usr/lib/jvm/jdk1.7.0_79/jre/lib/""
FilePath="/root/hss.sh"
LineNumber=2
sudo sed -i "${LineNumber}i${ContentToAdd}" "$FilePath"

###############################################
cd $HomeDirectory


sudo rm -r Kamailio_IMS_Config/
sudo rm apache-ant-1.9.14-bin.tar.gz 
sudo rm jdk-7u79-linux-x64.tar.gz 
sudo rm ngcp-rtpengine-daemon-dbgsym_9.4.1.6+0~mr9.4.1.6_amd64.ddeb ngcp-rtpengine-daemon_9.4.1.6+0~mr9.4.1.6_amd64.deb ngcp-rtpengine-iptables-dbgsym_9.4.1.6+0~mr9.4.1.6_amd64.ddeb ngcp-rtpengine-iptables_9.4.1.6+0~mr9.4.1.6_amd64.deb ngcp-rtpengine-kernel-dkms_9.4.1.6+0~mr9.4.1.6_all.deb ngcp-rtpengine-kernel-source_9.4.1.6+0~mr9.4.1.6_all.deb ngcp-rtpengine-recording-daemon-dbgsym_9.4.1.6+0~mr9.4.1.6_amd64.ddeb ngcp-rtpengine-recording-daemon_9.4.1.6+0~mr9.4.1.6_amd64.deb ngcp-rtpengine-utils_9.4.1.6+0~mr9.4.1.6_all.deb ngcp-rtpengine_9.4.1.6+0~mr9.4.1.6_all.deb ngcp-rtpengine_9.4.1.6+0~mr9.4.1.6_amd64.buildinfo ngcp-rtpengine_9.4.1.6+0~mr9.4.1.6_amd64.changes 
sudo rm -r rtpengine/
###############################################
sudo systemctl stop rtpproxy.service
sudo systemctl disable rtpproxy.service
sudo systemctl mask rtpproxy.service
sudo systemctl stop kamailio.service
sudo systemctl disable kamailio.service
sudo systemctl mask kamailio.service

bash /etc/open5gs/shortcut.sh restart

echo "#################################################################################################################################################################################################"
echo "##################################################################Installation and Configuration completed!\#####################################################################################"
echo "#################################################################################################################################################################################################"
echo "Kamailio and RTPProxy is masked"
echo "Check for the status of Open5gs. Restrat open5gs if you show some errors. Use the below commands:"
echo "bash /etc/open5gs/shortcut.sh restart"
echo "bash /etc/open5gs/shortcut.sh status"
echo "Check for DNS resloving by pinging to pcscf, icscf and scscf using the below commands:"
echo "ping pcscf"
echo "ping scscf"
echo "ping icscf"
echo "##################################################################Running PCSCF, SCSCF, ICSCF and FHoSS##########################################################################################"
echo "Open four new terminals for PCSCF, SCSCF, ICSCF and FHoSS and sudo su each of them."
echo "Run PCSCF:"
echo "mkdir -p /var/run/kamailio_pcscf"
echo "kamailio -f /etc/kamailio_pcscf/kamailio_pcscf.cfg -P /kamailio_pcscf.pid -DD -E -e"
echo "Run SCSCF:"
echo "mkdir -p /var/run/kamailio_scscf"
echo "kamailio -f /etc/kamailio_scscf/kamailio_scscf.cfg -P /kamailio_scscf.pid -DD -E -e"
echo "Run ICSCF:"
echo "mkdir -p /var/run/kamailio_icscf"
echo "kamailio -f /etc/kamailio_icscf/kamailio_icscf.cfg -P /kamailio_icscf.pid -DD -E -e"
echo "Run FHoSS:"
echo "cd ~"
echo "./hss.sh"
