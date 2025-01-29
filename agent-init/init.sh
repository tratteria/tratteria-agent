#!/bin/ash

set -o errexit
set -o nounset
set -o pipefail

usage() {
  echo "${0} -i INBOUND_PORT -p AGENT_PORT"
  echo ''
  echo '  -i: Specify the inbound TCP port to intercept and redirect to the Tokenetes Agent'
  echo '  -p: Specify the Tokenetes Agent port to which redirect all inbound TCP traffic'
  echo ''
}

INBOUND_PORT=""
AGENT_PORT=""

while getopts ":i:p:h" opt; do
  case ${opt} in
    i)
      INBOUND_PORT=${OPTARG}
      ;;
    p)
      AGENT_PORT=${OPTARG}
      ;;
    h)
      usage
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${INBOUND_PORT}" || -z "${AGENT_PORT}" ]]; then
  echo "Please set both -i and -p parameters."
  usage
  exit 1
fi

if ! iptables -t nat -L TRATTERIA_IN_REDIRECT &> /dev/null; then
  iptables -t nat -N TRATTERIA_IN_REDIRECT -m comment --comment "tokenetes/redirect-inbound-chain"
fi

iptables -t nat -F TRATTERIA_IN_REDIRECT

iptables -t nat -A TRATTERIA_IN_REDIRECT -p tcp --dport ${INBOUND_PORT} -j REDIRECT --to-port ${AGENT_PORT} -m comment --comment "tokenetes/redirect-to-tokenetes-inbound-port"

iptables -t nat -A PREROUTING -p tcp --dport ${INBOUND_PORT} -j TRATTERIA_IN_REDIRECT -m comment --comment "tokenetes/install-tokenetes-inbound-prerouting"

exit 0
