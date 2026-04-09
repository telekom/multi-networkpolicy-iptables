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

# teardown_file_common — base cleanup logic shared by all .bats files.
# Deletes the manifest (MANIFEST_FILE) and optional extra namespaces (CLEANUP_NAMESPACES).
# Each .bats file's teardown_file() MUST call this function:
#
#   teardown_file() {
#       teardown_file_common
#       # optional: additional cleanup
#   }
#
teardown_file_common() {
	if [ -n "${MANIFEST_FILE:-}" ]; then
		cd "$BATS_TEST_DIRNAME"
		echo "# Cleaning up: kubectl delete -f ${MANIFEST_FILE}" >&3
		if ! kubectl delete --ignore-not-found --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"; then
			echo "# WARNING: cleanup of ${MANIFEST_FILE} failed" >&3
		fi
	fi
	if [ -n "${CLEANUP_NAMESPACES:-}" ]; then
		for ns in ${CLEANUP_NAMESPACES}; do
			if ! kubectl delete namespace --ignore-not-found --wait --timeout=${kubewait_timeout} "${ns}"; then
				echo "# WARNING: cleanup of namespace ${ns} failed" >&3
			fi
		done
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

# wait_for_net1_ip6 waits for a non-empty net1 global IPv6 address on the given pod.
# IPv6 addresses may take time to appear due to DAD (Duplicate Address Detection).
# Usage: ip=$(wait_for_net1_ip6 <namespace> <pod-name>)
# Returns non-zero if the IP cannot be resolved within the timeout.
wait_for_net1_ip6() {
	local ns="$1" pod="$2" ip="" attempts=0
	while [ $attempts -lt 30 ]; do
		ip=$(kubectl exec -n "$ns" "$pod" -- ip -j a show 2>/dev/null | jq -r \
			'.[]|select(.ifname=="net1")|.addr_info[]|select(.family=="inet6" and .scope=="global").local' 2>/dev/null)
		if [ -n "$ip" ]; then
			echo "$ip"
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	echo "ERROR: could not resolve net1 IPv6 address for $ns/$pod after 30s" >&2
	return 1
}

# wait_for_net2_ip waits for a non-empty net2 IPv4 address on the given pod.
# Usage: ip=$(wait_for_net2_ip <namespace> <pod-name>)
# Returns non-zero if the IP cannot be resolved within the timeout.
wait_for_net2_ip() {
	local ns="$1" pod="$2" ip="" attempts=0
	while [ $attempts -lt 30 ]; do
		ip=$(kubectl exec -n "$ns" "$pod" -- ip -j a show 2>/dev/null | jq -r \
			'.[]|select(.ifname=="net2")|.addr_info[]|select(.family=="inet").local' 2>/dev/null)
		if [ -n "$ip" ]; then
			echo "$ip"
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	echo "ERROR: could not resolve net2 IP for $ns/$pod after 30s" >&2
	return 1
}

# wait_for_net2_ip6 waits for a non-empty net2 global IPv6 address on the given pod.
# IPv6 addresses may take time to appear due to DAD (Duplicate Address Detection).
# Usage: ip=$(wait_for_net2_ip6 <namespace> <pod-name>)
# Returns non-zero if the IP cannot be resolved within the timeout.
wait_for_net2_ip6() {
	local ns="$1" pod="$2" ip="" attempts=0
	while [ $attempts -lt 30 ]; do
		ip=$(kubectl exec -n "$ns" "$pod" -- ip -j a show 2>/dev/null | jq -r \
			'.[]|select(.ifname=="net2")|.addr_info[]|select(.family=="inet6" and .scope=="global").local' 2>/dev/null)
		if [ -n "$ip" ]; then
			echo "$ip"
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	echo "ERROR: could not resolve net2 IPv6 address for $ns/$pod after 30s" >&2
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
		sleep 2
		attempt=$((attempt + 1))
	done
	echo "# Command failed after $max_retries attempts: $*" >&3
	return 1
}


# retry_until_deny retries a command until it exits with non-zero status (i.e., traffic is blocked).
# This is needed because nft rules appearing in 'nft list ruleset' does not guarantee they are
# immediately effective for packet filtering (kernel asynchrony on bond/vlan interfaces).
# Usage: retry_until_deny <max_retries> <command...>
retry_until_deny() {
	local max_retries=$1
	shift
	local attempt=1
	while [ $attempt -le $max_retries ]; do
		local rc
		local last_output
		if last_output=$("$@" 2>&1); then
			rc=0
		else
			rc=$?
		fi
		if [ $rc -ne 0 ]; then
			return 0
		fi
		echo "# Deny attempt $attempt/$max_retries - traffic still allowed, retrying..." >&3
		sleep 2
		attempt=$((attempt + 1))
	done
	echo "# Deny failed after $max_retries attempts: traffic still not blocked by: $*" >&3
	return 1
}

# retry_until_allow retries a command until it exits with zero status (i.e., traffic is allowed).
# This is needed because nft rules appearing in 'nft list ruleset' does not guarantee they are
# immediately effective for packet filtering (kernel asynchrony on bond/vlan interfaces).
# Usage: retry_until_allow <max_retries> <command...>
retry_until_allow() {
	local max_retries=$1
	shift
	local attempt=1
	while [ $attempt -le $max_retries ]; do
		if "$@" 2>/dev/null; then
			return 0
		fi
		echo "# Allow attempt $attempt/$max_retries - traffic still blocked, retrying..." >&3
		sleep 2
		attempt=$((attempt + 1))
	done
	echo "# Allow failed after $max_retries attempts: traffic still not allowed by: $*" >&3
	return 1
}

# wait_for_nft_rules waits until nftables rules containing the given pattern appear in a pod.
# Usage: wait_for_nft_rules <namespace> <pod> <grep_pattern> [max_retries]
wait_for_nft_rules() {
	local ns=$1
	local pod=$2
	local pattern=$3
	local max_retries=${4:-30}
	retry_until_success "$max_retries" kubectl -n "$ns" exec "$pod" -- sh -c "nft list ruleset | grep -q '$pattern'"
}

# wait_for_connectivity_blocked polls until a connection attempt from src_pod to dst_ip:port fails.
# Use this in setup to confirm policy enforcement is active before testing the blocked direction.
# Usage: wait_for_connectivity_blocked <namespace> <src_pod> <dst_ip> <port> [timeout_seconds]
# Returns non-zero if the connection is still succeeding after the timeout.
wait_for_connectivity_blocked() {
	local ns="$1" pod="$2" dst_ip="$3" port="$4" timeout="${5:-30}" attempts=0
	while [ $attempts -lt $timeout ]; do
		# First verify the pod is reachable via exec (prevents false positives from
		# transient API errors being misinterpreted as "traffic blocked").
		if ! kubectl -n "$ns" exec "$pod" -- true 2>/dev/null; then
			sleep 1
			attempts=$((attempts + 1))
			continue
		fi
		if ! kubectl -n "$ns" exec "$pod" -- sh -c "echo x | nc -w 1 $dst_ip $port" 2>/dev/null; then
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	return 1
}

# wait_for_nft_rule_absent polls until the given pod no longer has an nft rule matching the pattern.
# Usage: wait_for_nft_rule_absent <namespace> <pod> <grep-pattern> [timeout_seconds]
# Returns non-zero if the rule is still present after the timeout.
wait_for_nft_rule_absent() {
	local ns="$1" pod="$2" pattern="$3" timeout="${4:-30}" attempts=0
	while [ $attempts -lt $timeout ]; do
		# First verify the pod is reachable via exec (prevents false positives from
		# transient API errors being misinterpreted as "rule absent").
		if ! kubectl -n "$ns" exec "$pod" -- true 2>/dev/null; then
			sleep 1
			attempts=$((attempts + 1))
			continue
		fi
		if ! kubectl -n "$ns" exec "$pod" -- sh -c "nft list ruleset 2>/dev/null | grep -q '$pattern'" 2>/dev/null; then
			return 0
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
	return 1
}

# setup_file — called by BATS before any test in a file runs.
# Each .bats file MUST override setup_file() to set MANIFEST_FILE,
# AND MUST define teardown_file() that calls teardown_file_common.
# CLEANUP_NAMESPACES is optional for multi-namespace tests (space-separated list of namespaces to delete).
