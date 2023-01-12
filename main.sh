#!/bin/bash

plain='\033[0m'
red='\033[0;31m'
blue='\033[1;34m'
pink='\033[1;35m'
green='\033[0;32m'
yellow='\033[0;33m'

OS_ARCH=''

HOME_PATH='/etc/headscale'

DATA_PATH='/var/lib/headscale'

TEMP_PATH='/var/run/headscale'

BINARY_FILE_PATH='/usr/local/bin/headscale'

SERVICE_FILE_PATH='/etc/systemd/system/headscale.service'

declare -r STATUS_RUNNING=1
declare -r STATUS_NOT_RUNNING=0
declare -r STATUS_NOT_INSTALL=255

function LOGE() {
  echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
  echo -e "${green}[INF] $* ${plain}"
}

function LOGD() {
  echo -e "${yellow}[DEG] $* ${plain}"
}

arch_check() {
  LOGI "Detect the current system architecture."
  OS_ARCH=$(arch)
  LOGI "The current system architecture is ${OS_ARCH}"
  if [[ ${OS_ARCH} == "x86_64" || ${OS_ARCH} == "x64" || ${OS_ARCH} == "amd64" ]]; then
    OS_ARCH="amd64"
  elif [[ ${OS_ARCH} == "aarch64" || ${OS_ARCH} == "arm64" ]]; then
    OS_ARCH="arm64"
  else
    OS_ARCH="amd64"
    LOGE "Failed to detect system architecture, making use of default architecture: ${OS_ARCH}"
  fi
  LOGI "After the system architecture detection is completed, the current system architecture is ${OS_ARCH}."
}

create_or_delete_path() {
  if [[ $# -ne 1 ]]; then
    LOGE "invalid input,should be one paremete,and can be 0 or 1"
    exit 1
  fi
  if [[ "$1" == "1" ]]; then
    LOGI "Will create ${HOME_PATH} and ${DATA_PATH} and ${TEMP_PATH} for headscale..."
    rm -rf ${HOME_PATH} ${DATA_PATH} ${TEMP_PATH} /home/headscale
    mkdir -p ${HOME_PATH} ${DATA_PATH} ${TEMP_PATH} /home/headscale
    if [[ $? -ne 0 ]]; then
      LOGE "create ${HOME_PATH} and ${DATA_PATH} and ${TEMP_PATH} for headscale failed"
      exit 1
    else
      LOGI "create ${HOME_PATH} adn ${DATA_PATH} and ${TEMP_PATH} for headscale success"
    fi
  elif [[ "$1" == "0" ]]; then
    LOGI "Will delete ${HOME_PATH} and ${DATA_PATH} and ${TEMP_PATH}..."
    rm -rf ${HOME_PATH} ${DATA_PATH} ${TEMP_PATH} /home/headscale
    if [[ $? -ne 0 ]]; then
      LOGE "delete ${HOME_PATH} and ${DATA_PATH} and ${TEMP_PATH} failed"
      exit 1
    else
      LOGI "delete ${HOME_PATH} and ${DATA_PATH} and ${TEMP_PATH} success"
    fi
  fi
}

download_headscale() {
  LOGD "Downloading HEADscale..._rrrrrrrrr!"
  arch_check

  local headscale_version_temp=$(curl -Ls "https://api.github.com/repos/juanfont/headscale/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  headscale_version=${headscale_version_temp:1}

  LOGI "Choosing this specific version: ${headscale_version}"
  local DOWANLOAD_URL="https://github.com/juanfont/headscale/releases/download/${headscale_version_temp}/headscale_${headscale_version}_linux_${OS_ARCH}"

  create_or_delete_path 1
  wget --output-document=${BINARY_FILE_PATH} ${DOWANLOAD_URL}

  chmod +x ${BINARY_FILE_PATH}

  if [[ $? -ne 0 ]]; then
    LOGE "Download headscale failed,plz be sure that your network work properly and can access github"
    create_or_delete_path 0
    exit 1
  else
    LOGI "HEADscale download suXoxFUL; Yeah downloaded da."
  fi
}

install_service() {
  LOGD "[💉] Injecting HeadScale on systemd."
  if [ -f "${SERVICE_FILE_PATH}" ]; then
    rm -rf ${SERVICE_FILE_PATH}
  fi
  touch ${SERVICE_FILE_PATH}
  if [ $? -ne 0 ]; then
    LOGE "Creation of service file contaminated, Terminating.."
    exit 1
  else
    LOGI "Creation of service file done!"
  fi
  cat >${SERVICE_FILE_PATH} <<EOF
[Unit]
Description=headscale controller
After=syslog.target
After=network.target
[Service]
Type=simple
User=headscale
Group=headscale
ExecStart=${BINARY_FILE_PATH} serve
Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_PATH} ${TEMP_PATH}
AmbientCapabilities=CAP_NET_BIND_SERVICE
RuntimeDirectory=headscale

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 ${SERVICE_FILE_PATH}
  systemctl daemon-reload
  LOGD "Installation of headscale on systemd went all correct. =)"
}

config_headscale() {
  touch ${DATA_PATH}/db.sqlite

  useradd headscale -d /home/headscale -m
  chown -R headscale:headscale ${DATA_PATH}

  touch ${HOME_PATH}/config.yaml
  if [ $? -ne 0 ]; then
    LOGE "create config.yaml file failed,exit"
    exit 1
  else
    LOGI "create config.yaml file success..."
  fi

  ip=`curl -sL -4 ip.sb`

  echo ""
  read -p "Enter a number 4Da' service port [100-65535, default 8080]：" port
  [[ -z "${port}" ]] && port=8080
  if [[ "${port:0:1}" = "0" ]]; then
    LOGE "GET SOME HELP: ${plain} [https://en.wikipedia.org/wiki/Port_(computer_networking)]"
    exit 1
  fi
  LOGI "Serving on service address： <proto>://${ip}:${port}"

  cat >${HOME_PATH}/config.yaml <<EOF
server_url: http://${ip}:${port}
listen_addr: 0.0.0.0:${port}
metrics_listen_addr: 127.0.0.1:9090

grpc_listen_addr: 0.0.0.0:50443
grpc_allow_insecure: false

private_key_path: ${DATA_PATH}/private.key
noise:
  private_key_path: ${DATA_PATH}/noise_private.key

ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 172.16.0.0/16

derp:
  server:
    enabled: false
    region_id: 999
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    stun_listen_addr: "0.0.0.0:3478"
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: true
  update_frequency: 24h

disable_check_updates: false
ephemeral_node_inactivity_timeout: 30m
node_update_check_interval: 10s

db_type: sqlite3
db_path: ${DATA_PATH}/db.sqlite

acme_url: https://acme-v02.api.letsencrypt.org/directory
acme_email: ""
tls_letsencrypt_hostname: ""
tls_client_auth_mode: relaxed
tls_letsencrypt_cache_dir: ${DATA_PATH}/cache
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"
tls_cert_path: ""
tls_key_path: ""

log:
  format: text
  level: info

acl_policy_path: ""

dns_config:
  override_local_dns: true
  nameservers:
    - 1.0.0.1
  domains: []
  magic_dns: false
  base_domain: google.com

unix_socket: ${TEMP_PATH}/headscale.sock
unix_socket_permission: "0770"

logtail:
  enabled: false

randomize_client_port: false
EOF
}

enable_headscale() {
  systemctl enable headscale
  if [[ $? == 0 ]]; then
    LOGI "Boot sequence complete - Set da headscale up!"
  else
    LOGE "Boot sequence failure - headscale DOWN. FIX IT THY_SELF."
  fi
}

start_headscale() {
  if [ -f "${SERVICE_FILE_PATH}" ]; then
    systemctl start headscale
    sleep 1s
    status_check
    if [ $? == ${STATUS_NOT_RUNNING} ]; then
      LOGE "start headscale service failed,exit"
      exit 1
    elif [ $? == ${STATUS_RUNNING} ]; then
      LOGI "start headscale service success"
    fi
  else
    LOGE "${SERVICE_FILE_PATH} does not exist,can not start service"
    exit 1
  fi
}

restart_headscale() {
  if [ -f "${SERVICE_FILE_PATH}" ]; then
    systemctl restart headscale
    sleep 1s
    status_check
    if [ $? == 0 ]; then
      LOGE "restart headscale service failed,exit"
      exit 1
    elif [ $? == 1 ]; then
      LOGI "restart headscale service success"
    fi
  else
    LOGE "${SERVICE_FILE_PATH} does not exist,can not restart service"
    exit 1
  fi
}

stop_headscale() {
  LOGD "init/exit headscale service..."
  status_check
  if [ $? == ${STATUS_NOT_INSTALL} ]; then
    LOGE "headscale did not install,can not stop it"
    exit 1
  elif [ $? == ${STATUS_NOT_RUNNING} ]; then
    LOGI "headscale already stoped,no need to stop it again"
    exit 1
  elif [ $? == ${STATUS_RUNNING} ]; then
    if ! systemctl stop headscale; then
      LOGE "stop headscale service failed,plz check logs"
      exit 1
    fi
  fi
  LOGD "Termination of headscale done. #peace"
}

install_headscale() {
  LOGD "Installing headscale KEEP YOUR HEAD UP kid. <3"
  if [[ $# -ne 0 ]]; then
    download_headscale $1
  else
    download_headscale
  fi

  config_headscale
  install_service

  enable_headscale && start_headscale
  headscale namespaces create default
  LOGI "Installation as well as service initiation of headscale's done!"
}

uninstall_headscale() {
  echo ""
  LOGD "Initiate Uninstall sequence of headscale."
  pidOfheadscale=$(pidof headscale)
  if [ -n ${pidOfheadscale} ]; then
    stop_headscale
  fi

  create_or_delete_path 0 && rm -rf ${SERVICE_FILE_PATH} && rm -rf ${BINARY_FILE_PATH}
  userdel -r headscale
  groupdel headscale

  if [ $? -ne 0 ]; then
    LOGE "Some technical disability detected for headscale initiation. Check da logs."
    exit 1
  else
    LOGI "Removal headscale was successful."
  fi
}

register_node() {
  echo ""
  while true
  do
    read -p "请输入key：" key
    if [[ -z "${key}" ]]; then
      LOGE "输入错误，请重新输入！${plain}"
    else
      break
    fi
  done
  LOGI "输入的key为：$key"
  headscale -n default nodes register --key $key
  headscale nodes list
}

status_check() {
  if [[ ! -f "${SERVICE_FILE_PATH}" ]]; then
    return ${STATUS_NOT_INSTALL}
  fi
  temp=$(systemctl status headscale | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
  if [[ x"${temp}" == x"running" ]]; then
    return ${STATUS_RUNNING}
  else
    return ${STATUS_NOT_RUNNING}
  fi
}

show_status() {
  status_check
  case $? in
  0)
    echo -e "[INF] headscale-State: ${yellow}Dead.${plain}"
    ;;
  1)
    echo -e "[INF] headscale-State: ${green}Running!${plain}"
    ;;
  255)
    echo -e "[INF] headscale-State: ${red}Dead for real :|${plain}"
    ;;
  esac
}

show_menu() {
  echo -e "
  ${green}headscale Managemen!4Å script${plain}
  ${green}0.${plain} Terminate self.
  ${green}1.${plain} Install.
  ${green}2.${plain} Uninstall.
  ${green}3.${plain} Initiate service.
  ${green}4.${plain} Out of service.
  ${green}5.${plain} Re-initiate service.
  ${green}6.${plain} Vue.i3 Node ;)
  ${green}7.${plain} [+] Node <3 🤌 [✌️]
 "
  show_status
  echo && read -p "Enter ur numbba ~> [0-7]: " num
  case "${num}" in
  0)
    exit 0
    ;;
  1)
    install_headscale && show_menu
    ;;
  2)
    uninstall_headscale && show_menu
    ;;
  3)
    start_headscale && show_menu
    ;;
  4)
    stop_headscale && show_menu
    ;;
  5)
    restart_headscale && show_menu
    ;;   
  6)
    headscale nodes list && show_menu
  ;;  
  7)
    register_node && show_menu
  ;; 
  *)
    LOGE "Choose a valid one bro. [0-7]"
    ;;
  esac
}

start_to_run() {
  clear
  show_menu
}

start_to_run
