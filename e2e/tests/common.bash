# Common code for bats

kubewait_timeout=300s

get_net1_ip() {
	if [ "$#" == "2" ]; then
		echo $(kubectl exec -n $1 "$2" -- ip -j a show  | jq -r \
			 '.[]|select(.ifname =="net1")|.addr_info[]|select(.family=="inet").local')
	else
		echo "unknown ip $1"
	fi
}

get_net1_ip6() {
	if [ "$#" == "2" ]; then
		echo $(kubectl exec -n $1 "$2" -- ip -j a show  | jq -r \
			 '.[]|select(.ifname =="net1")|.addr_info[]|select(.family=="inet6" and .scope=="global").local')
	else
		echo "unknown ip $1"
	fi
}

get_net2_ip() {
	if [ "$#" == "2" ]; then
		echo $(kubectl exec -n $1 "$2" -- ip -j a show  | jq -r \
			 '.[]|select(.ifname =="net2")|.addr_info[]|select(.family=="inet").local')
	else
		echo "unknown ip $1"
	fi
}

get_net2_ip6() {
	if [ "$#" == "2" ]; then
		echo $(kubectl exec -n $1 "$2" -- ip -j a show  | jq -r \
			 '.[]|select(.ifname =="net2")|.addr_info[]|select(.family=="inet6" and .scope=="global").local')
	else
		echo "unknown ip $1"
	fi
}

# wait_for_net1_ip waits for a non-empty net1 IPv4 address on the given pod.
# Usage: ip=$(wait_for_net1_ip <namespace> <pod-name>)
# Returns non-zero if the IP cannot be resolved within the timeout.
wait_for_net1_ip() {
	local ns="$1" pod="$2" ip="" attempts=0
	while [ $attempts -lt 30 ]; do
		ip=$(kubectl exec -n "$ns" "$pod" -- ip -j a show 2>/dev/null | jq -r \
			'.[]|select(.ifname=="net1")|.addr_info[]|select(.family=="inet").local' 2>/dev/null)
		if [ -n "$ip" ]; then
			echo "$ip"
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	echo "ERROR: could not resolve net1 IP for $ns/$pod after 30s" >&2
	return 1
}

# wait_for_nft_rule polls until the given pod has an nft rule matching the pattern.
# Usage: wait_for_nft_rule <namespace> <pod> <grep-pattern> [timeout_seconds]
wait_for_nft_rule() {
	local ns="$1" pod="$2" pattern="$3" timeout="${4:-30}" attempts=0
	while [ $attempts -lt $timeout ]; do
		if kubectl -n "$ns" exec "$pod" -- sh -c "nft list ruleset 2>/dev/null | grep -q '$pattern'" 2>/dev/null; then
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	return 1
}

# retry_until_success retries a command up to $1 times with 1-second intervals.
# Usage: retry_until_success <max_retries> <command...>
retry_until_success() {
	local max_retries=$1
	shift
	local attempt=1
	while [ $attempt -le $max_retries ]; do
		if "$@"; then
			return 0
		fi
		echo "# Attempt $attempt/$max_retries failed, retrying..." >&3
		sleep 1
		attempt=$((attempt + 1))
	done
	echo "# Command failed after $max_retries attempts: $*" >&3
	return 1
}

# wait_for_nft_rules waits until nftables rules containing the given pattern appear in a pod.
# Usage: wait_for_nft_rules <namespace> <pod> <grep_pattern> [max_retries]
wait_for_nft_rules() {
	local ns=$1
	local pod=$2
	local pattern=$3
	local max_retries=${4:-15}
	retry_until_success "$max_retries" kubectl -n "$ns" exec "$pod" -- sh -c "nft list ruleset | grep -q '$pattern'"
}
