# AutomationScritp_for_Open5GS_and_Kamailio_Installation-Configuration

For establishig a private EPC that supports VoLTE, we need EPC and IMS both. Open5GS is an opensource EPC which is widely used for private EPC and 5G core. We deploy this core along with Kamailio which is an open source SIP Server that provides IMS functionalities. Besides Open5GS and Kamailio, we need some more modules and packages namely RTPProxy, RTPEngine and FHoSS.

Installation of Open5gs, Kamailio, RTPProxy, RTPEngine and FHoSS takes a handful of commands to be run manually. Moreover, a lot of files are generated during these installations which need to be configured as well. This process is lengthy and takes a lot of time. At the same time, it is a complicated process, as any unconscious error may lead to a fatal consequence and the programs may not work properly. So, a shell script has been developed that will automatically do all these manual installations and configurations.

# INSTRUCTION
Follow the steps below,

**1.** Make a .env file in /home/<user> location.

    nano .env

The content will be as like below as per your specification

    MACHINE_IP="192.168.0.252"
    M_C_C="001"
    M_N_C="01"
    T_A_C="1"
    IMS_DOMAIN_NAME="ims.mnc001.mcc001.3gppnetwork.org"
    EPC_DOMAIN_NAME="epc.mnc001.mcc001.3gppnetwork.org"

**2.** Make a modules.lst file in /home/<user>

    nano modules.lst

The content will be exactly the same as below,

    #this file is autogenerated by make modules-cfg

    # the list of sub-directories with modules
    modules_dirs:=modules

    # the list of module groups to compile
    cfg_group_include=

    # the list of extra modules to compile
    include_modules= cdp cdp_avp db_mysql dialplan enum json http_client ims_auth ims_charging ims_dialog ims_diameter_server ims_icscf ims_ipsec_pcscf ims_isc ims_ocs ims_qos ims_registrar_pcscf ims_registrar_scscf ims_usrloc_pcscf ims_usrloc_scscf outbound presence presence_conference presence_dialoginfo presence_mwi presence_profile presence_reginfo presence_xml pua pua_bla pua_dialoginfo pua_reginfo pua_rpc pua_usrloc pua_xmpp sctp tls utils xcap_client xcap_server xmlops xmlrpc

    # the list of static modules
    static_modules=#

    # the list of modules to skip from compile list
    skip_modules=

    # the list of modules to exclude from compile list
    exclude_modules= acc_json acc_radius app_java app_lua app_lua_sr app_mono app_perl app_python app_python3 app_ruby auth_ephemeral auth_identity auth_radius cnxcc cplc crypto db2_ldap db_berkeley db_cassandra db_mongodb db_oracle db_perlvdb db_postgres db_redis db_sqlite db_unixodbc dnssec erlang evapi geoip geoip2 gzcompress h350 http_async_client jansson janssonrpcc jsonrpcc jwt kafka kazoo lcr ldap log_systemd lost lwsc memcached misc_radius ndb_cassandra mqtt ndb_mongodb ndb_redis nsq osp peering phonenum pua_json rabbitmq regex rls rtp_media_server secsipid secsipid_proc snmpstats stirshaken systemdops topos_redis uuid websocket xhttp_pi xmpp $(skip_modules)

    modules_all= $(filter-out modules/CVS,$(wildcard modules/*))
    modules_noinc= $(filter-out $(addprefix modules/, $(exclude_modules) $(static_modules)), $(modules_all)) 
    modules= $(filter-out $(modules_noinc), $(addprefix modules/, $(include_modules) )) $(modules_noinc) 
    modules_configured:=1

**3.** Make mysql.cnf file in /home/<user> The content will be exactly the same as below,

    [mysqldump]
    user=root
    password=\n

**4.** As mysql.cnf is created, run the below command in the same directory for permission.

    sudo chmod 600 mysql.cnf

**5.** Locate autoVoLTE.sh file in /home/<user> directory. Open this file using any text editor and edit the value of variable “HomeDirectory” occurs in #line 6 according to your home directory. Also edit #line 974 “source /home/vagrant/.env” according to the directory of your .env file.

**6.** Now provide permission and run the script.

    sudo chmod +x autoVoLTE.sh
    sudo ./autoVoLTE.sh

It takes time to complete the program.

# Re-running autoVoLTE.sh:
If the script autoVoLTE.sh gets stopped meanwhile during running, you can easily re-run it. Before that check the status of Kamailio and RTPProxy. If you find these are installed and masked, then unmask and enable them first.

    sudo systemctl unmask kamailio.service
    sudo systemctl enable kamailio.service
    sudo systemctl start kamailio.service
    sudo systemctl unmask rtpproxy.service
    sudo systemctl enable rtpproxy.service
    sudo systemctl start rtpproxy.service

# Check:

After successful running of the program, check these few steps to ensure everything has been installed and configured successfully.

**1.** Check status of Open5gs. You may see some errors. In that case just restart Open5gs and check status once again.

    bash /etc/open5gs/shortcut.sh restart
    bash /etc/open5gs/shortcut.sh status

**2.** Check the status of MongoDB and RTPEngine as well.

**3.** Check Databases with their tables. There will be databases for Kamailio, PCSCF, SCSCF, ICSCF and IMS (hss_db). hss_db is already poplulated with two sample subscribers. Check for their existence.

    sudo mysql;
    show databases;
    use <database_name>;
    show tables;
    select * from <table_name>

**4.** PING PCSCF, SCSCF and ICSCF to test DNS resolving.

# Start VoLTE:

When the script has run successfully and we have checked that everything has been installed and configured, then we can start VoLTE. Follow these steps for starting VoLTE.

**1.** Open four new terminals for PCSCF, SCSCF, ICSCF and FHoSS. Then sudo su each of them.

**2.** Run PCSCF: 

    mkdir -p /var/run/kamailio_pcscf
    kamailio -f /etc/kamailio_pcscf/kamailio_pcscf.cfg -P /kamailio_pcscf.pid -DD -E -e

**3.** Run SCSCF: 

    mkdir -p /var/run/kamailio_scscf
    kamailio -f /etc/kamailio_scscf/kamailio_scscf.cfg -P /kamailio_scscf.pid -DD -E -e

**4.** Run ICSCF:

    mkdir -p /var/run/kamailio_icscf
    kamailio -f /etc/kamailio_icscf/kamailio_icscf.cfg -P /kamailio_icscf.pid -DD -E -e

**5.** Run FHoSS:

    cd ~
    ./hss.sh


    
