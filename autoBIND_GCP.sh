#!/bin/bash

set -a
set -e

HomeDirectory="/home/ashiq"

source $HomeDirectory/.env

##############################EDIT /etc/resolv.conf############################################
sudo cp /etc/resolv.conf /etc/resolve.backup

sudo echo "nameserver $MACHINE_IP" | cat - /etc/resolv.conf  > temp && mv temp /etc/resolv.conf
search_domains=$(grep "^search" "/etc/resolv.conf" | awk '{$1=""; print $0}')
sudo sed -i '/^search/d' /etc/resolv.conf
sudo echo "search $IMS_DOMAIN_NAME $EPC_DOMAIN_NAME $search_domains" >> /etc/resolv.conf
################################EDIT /etc/netplan/50-cloud-init.yaml######################################
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.backup

tmp_file=$(mktemp)

sudo sed "/set-name: ens4/ {
        a \\
            nameservers: \\
                search: [$IMS_DOMAIN_NAME,$EPC_DOMAIN_NAME] \\
                addresses: \\
                    - $MACHINE_IP
    }" "/etc/netplan/50-cloud-init.yaml" > "$tmp_file"

sudo mv "$tmp_file" "/etc/netplan/50-cloud-init.yaml"

sudo netplan apply
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved.service
