#!/bin/bash
COMPOSE_FILE=${COMPOSE_FILE:-"docker-compose.yml"}

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "[ERROR] ${COMPOSE_FILE} file not found!!"
  exit 1
fi



CONTAINER_NAME=$(grep -w "container_name" ${COMPOSE_FILE} | awk -F':' '{print $2}' | tr -d '" ')
CONTAINER_STATUS=$(docker ps -q -f name="${CONTAINER_NAME}")
RUN_COMMAND="docker exec -it $CONTAINER_NAME "

if [[ -z "${CONTAINER_STATUS}" || "${CONTAINER_NAME}" != "havah-chain-node" ]]; then
  echo "[WARN] [ ${CONTAINER_NAME} ] is not running."
  RUN_COMMAND="docker run --rm -v ${PWD}/config:/goloop/config -v ${PWD}/logs:/goloop/logs -v ${PWD}/data:/goloop/data -it --name temp-node havah/chain-node"
fi




if [[ "$#" -eq 1 ]]; then
  case "$1" in
    check_wallet)
      ${RUN_COMMAND} havah_wallet.py get
      ;;
    create_wallet)
      ${RUN_COMMAND} havah_wallet.py create
      ;;
    check_node)
      ${RUN_COMMAND} check_my_node.py
      ;;
    send_log)
      ${RUN_COMMAND} sendme_log.py
      ;;
    *)
      echo "[ERROR] Select one of the [ check_wallet, create_wallet, check_node, send_log ]"
      exit 1
      ;;
  esac
else
  echo "[ERROR] Number of arguments must be one. Select one of [ check_wallet, create_wallet, check_node, send_log ]"
  exit 1
fi
