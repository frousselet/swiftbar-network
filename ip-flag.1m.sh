
#!/usr/bin/env bash

# <xbar.title>Network info</xbar.title>
# <xbar.version>v1.0</xbar.version>
# <xbar.author>François Rousselet</xbar.author>
# <xbar.author.github>frousselet</xbar.author.github>
# <xbar.desc>Display network information on the macOS menu bar</xbar.desc>
# <xbar.dependencies>OS X 10.11</xbar.dependencies>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideLastUpdated>true</swiftbar.hideLastUpdated>
# <swiftbar.hideDisablePlugin>true</swiftbar.hideDisablePlugin>
# <swiftbar.hideSwiftBar>true</swiftbar.hideSwiftBar>

# --- Detect system language ---
lang=$(defaults read -g AppleLanguages | awk -F'"' 'NR==2{print $2}' | cut -d'-' -f1)

# --- Define translations (FR/EN) ---
case "$lang" in
  fr)
    menu_external_ip="IP Publique"
    menu_city="Ville"
    menu_country="Pays"
    menu_timezone="Fuseau horaire"
    menu_open_in_maps="→ Ouvrir dans Apple Plans 􀙊"
    menu_network="Réseau"
    menu_ipv4="IPv4"
    menu_ipv6="IPv6"
    menu_local_ipv4="IPv4 (Locale)"
    menu_local_ipv6="IPv6 (Locale)"
    menu_pub_ipv4="IPv4 (Publique)"
    menu_pub_ipv6="IPv6 (Publique)"
    menu_dns_ipv4="DNS IPv4"
    menu_dns_ipv6="DNS IPv6"
    menu_gateway_ipv4="Passerelles IPv4"
    menu_gateway_ipv6="Passerelles IPv6"
    menu_host_ipv4="Hôte IPv4"
    menu_host_ipv6="Hôte IPv6"
    menu_tags="Tags"
    menu_wifi="Wi-Fi"
    menu_search_domains="Domaines"
    menu_derp="DERP"
    menu_tailscale="Tailscale"
    menu_pairs="Pairs"
    menu_ts_exit_config="Exit node configuré"
    menu_ts_exit_active="Tailscale exit node"
    menu_ts_admin="→ Ouvrir dans la console d'administration Tailscale"
    menu_host_name="Nom d'hôte"
    ;;
  *)
    menu_external_ip="External IP"
    menu_city="City"
    menu_country="Country"
    menu_timezone="Time zone"
    menu_open_in_maps="→ Open in Apple Maps 􀙊"
    menu_network="Network"
    menu_ipv4="IPv4"
    menu_ipv6="IPv6"
    menu_local_ipv4="IPv4 (Local)"
    menu_local_ipv6="IPv6 (Local)"
    menu_pub_ipv4="IPv4 (Public)"
    menu_pub_ipv6="IPv6 (Public)"
    menu_dns_ipv4="IPv4 DNS"
    menu_dns_ipv6="IPv6 DNS"
    menu_gateway_ipv4="IPv4 gateways"
    menu_gateway_ipv6="IPv6 gateways"
    menu_host_ipv4="IPv4 host"
    menu_host_ipv6="IPv6 host"
    menu_tags="Tags"
    menu_wifi="Wi-Fi"
    menu_search_domains="Search domains"
    menu_derp="DERP"
    menu_tailscale="Tailscale"
    menu_pairs="Pairs"
    menu_ts_exit_config="Exit node configured"
    menu_ts_exit_active="Tailscale exit node"
    menu_ts_admin="→ Open in Tailscale Admin Console"
    menu_host_name="Host name"
    ;;
esac

# --- Fetch IP info ---
json4=$(curl -4 -s http://ifconfig.co/json)
json6=$(curl -6 -s http://ifconfig.co/json)
if [[ -z "$json4" && -z "$json6" ]]; then
  echo "􁣡"
  echo "---"
  echo "Erreur: impossible de récupérer les infos IP | refresh=true"
  exit 1
fi
json="${json4:-$json6}"

# --- Parse JSON ---
country_iso=$(jq -r '.country_iso' <<<"$json")
country=$(jq -r '.country // empty' <<<"$json")
asn_org=$(jq -r '.asn_org' <<<"$json")
asn=$(jq -r '.asn' <<<"$json")
city=$(jq -r '.city // empty' <<<"$json")
tz=$(jq -r '.time_zone // empty' <<<"$json")
hostname4=$(jq -r '.hostname // empty' <<<"$json")
country_eu=$(jq -r '.country_eu // empty' <<<"$json")

# --- Parse IPs from saved JSON ---
pub_ip4=$(jq -r '.ip // empty' <<< "$json4")
pub_ip6=$(jq -r '.ip // empty' <<< "$json6")
# Remove any scope suffix from public IPv6
pub_ip6=${pub_ip6%%\%*}
# Ignore non-IPv6 results (fallback to IPv4)
if [[ -n "$pub_ip6" && "$pub_ip6" != *:* ]]; then pub_ip6=""; fi

# --- Fetch IPv4 and IPv6 addresses ---
# --- Fetch local IPv4 address ---
iface=$(route get default 2>/dev/null | awk '/interface:/ {print $2}')
local_ip4=$(ipconfig getifaddr "$iface" 2>/dev/null || echo "")
# --- Fetch local IPv6 address ---
# Use the same interface as IPv4
local_ip6=$(ifconfig "$iface" 2>/dev/null \
  | awk '/inet6 / && !/fe80/ {print $2; exit}' \
  | sed 's/%.*//')
ip6="$local_ip6"
# --- Fetch hostname for IPv6 and deduplicate ---
hostname6=""

# --- Build flag emoji ---
flag=""
for ((i=0; i<${#country_iso}; i++)); do
  c=${country_iso:i:1}
  ord=$(printf '%d' "'$c")
  reg=$((ord + 127397))
  flag+=$(perl -CO -e "print chr($reg)")
done

# --- Special: ASN name simplifications and network icon ---
network_icon="􀤆"
case "$asn_org" in
  "Free SAS") asn_org_f="Free" ;;
  "Free Pro SAS") asn_org_f="Free Pro" ;;
  "OVH SAS") asn_org_f="OVH" ;;
  "Societe Francaise Du Radiotelephone - SFR SA") asn_org_f="SFR" ;;
  "ZAYO-6461") asn_org_f="Zayo" ;;
  "Free Mobile SAS") asn_org_f="Free Mobile"; network_icon="􀖀" ;;
  "Iguane Solutions SAS"|"IGUANA-WORLDWIDE") asn_org_f="IG1" ;;
  "VNPT Corp"|"VIETNAM POSTS AND TELECOMMUNICATIONS GROUP") asn_org_f="VNPT" ;;
  "AKAMAI-AS") asn_org_f="Akamai" ;;
  "CLOUDFLARENET") asn_org_f="Cloudflare" ;;
  "Assistance Publique Hopitaux De Paris") asn_org_f="APHP" ;;
  "Kaopu Cloud HK Limited") asn_org_f="Kaopu Cloud" ;;
  *) asn_org_f="$asn_org" ;;
esac

# --- Fetch ISP icon or fallback favicon, and encode to base64 ---
org_fmt=$(echo "$asn_org" | tr '[:upper:]' '[:lower:]' | sed 's/ /_/g')
image_url="https://static.ui.com/isp/${org_fmt}_51x51.png"
whois_domain=$(whois "$asn" \
  | grep -i abuse-mailbox \
  | cut -d: -f2 \
  | xargs \
  | cut -d@ -f2)
favicon_url="https://t3.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${whois_domain}&size=32"

# Check HTTP status before downloading the ISP icon
status=$(curl -s -o /dev/null -w '%{http_code}' "$image_url")
if [[ "$status" == "200" ]]; then
  image_enc=$(curl -sSL "$image_url" | base64)
else
  image_enc=$(curl -sSL "$favicon_url" | base64)
fi

# --- SwiftBar / xbar display ---
echo "${network_icon}  ${asn_org_f}"
echo "---"
echo "| image=${image_enc} refresh=true"
# echo "---"

# Show ASN operator name and clickable AS numbers
asn4=$(jq -r '.asn // empty' <<<"$json4")
asn6=$(jq -r '.asn // empty' <<<"$json6")
if [[ -n "$asn4" && -n "$asn6" ]]; then
  if [[ "$asn4" == "$asn6" ]]; then
    echo "${asn_org} • $asn4 | href=https://whois.ipinsight.io/$asn4 refresh=true"
  else
    echo "${asn_org} • $asn6 • $asn4 | href=https://whois.ipinsight.io/$asn6 refresh=true"
  fi
elif [[ -n "$asn4" ]]; then
  echo "${asn_org} • $asn4 | href=https://whois.ipinsight.io/$asn4 refresh=true"
elif [[ -n "$asn6" ]]; then
  echo "${asn_org} • $asn6 | href=https://whois.ipinsight.io/$asn6 refresh=true"
fi
echo "---"
[[ -n "$city"   ]] && echo "${menu_city} : $city | refresh=true"
if [[ -n "$country" ]]; then
  if [[ "$country_eu" == "true" ]]; then
    echo "${menu_country} : $country $flag 🇪🇺 | refresh=true"
  else
    echo "${menu_country} : $country $flag | refresh=true"
  fi
fi
[[ -n "$tz"     ]] && echo "${menu_timezone} : $tz | refresh=true"
echo
if [[ -n "$city" || -n "$country" ]]; then
  query=$(printf '%s %s' "$city" "$country" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/ /%20/g')
  echo "${menu_open_in_maps} | href=maps://?q=${query} refresh=true"
fi

# --- DNS servers ---
dns_servers=$(scutil --dns | awk -v iface="$iface" '
  /^resolver / {inres=0}
  /if_index:.*\('"$iface"'\)/ {inres=1}
  inres && /nameserver\[[0-9]+\]/ {print $3}
' | sort -u)
dns_arr=()
while IFS= read -r d; do
  dns_arr+=("$d")
done <<<"$dns_servers"
dns4=""
dns6=""
for d in "${dns_arr[@]}"; do
  # Remove any scope suffix (e.g. %en0) from DNS entries
  d=${d%%\%*}
  if [[ "$d" == *:* ]]; then
    dns6+="${d} • "
  else
    dns4+="${d} • "
  fi
done
# Remove trailing delimiter
dns4=${dns4%% • }
dns6=${dns6%% • }

# Fallback: if no DNS found for interface, show all DNS
if [[ -z "$dns4" && -z "$dns6" ]]; then
  dns_servers=$(scutil --dns | awk '/nameserver\[[0-9]+\] :/ {print $3}' | sort -u)
  dns_arr=()
  while IFS= read -r d; do
    dns_arr+=("$d")
  done <<<"$dns_servers"
  dns4=""
  dns6=""
  for d in "${dns_arr[@]}"; do
    # Remove any scope suffix (e.g. %en0) from DNS entries
    d=${d%%\%*}
    if [[ "$d" == *:* ]]; then
      dns6+="${d} • "
    else
      dns4+="${d} • "
    fi
  done
  dns4=${dns4%% • }
  dns6=${dns6%% • }
fi

# --- Default gateways ---
gw4=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
gw6=$(route -n get -inet6 default 2>/dev/null | awk '/gateway:/ {print $2}')
# Remove any scope suffix from IPv6 gateway
gw6=${gw6%%\%*}

echo "---"
# --- Tailscale info (single call) ---
if command -v tailscale &>/dev/null; then
  ts_json=$(tailscale status --json --peers 2>/dev/null)
  ts_online=$(echo "$ts_json" | jq -r '.Self.Online // false')
else
  ts_json=""
  ts_online="false"
fi

# --- Network Tailscale IPs (single call) ---
if [[ "$ts_online" == "true" ]]; then
  ts_ip4=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]? | select(test(":") | not)' | head -n1)
  ts_ip6=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]? | select(test(":"))' | head -n1)
  # Remove any scope suffix from Tailscale IPv6
  ts_ip6=${ts_ip6%%\%*}
else
  ts_ip4=""
  ts_ip6=""
fi

# Network information
echo "${menu_network}"
[[ -n "$(hostname)" ]] && echo "${menu_host_name} : $(hostname) | refresh=true"
# --- Search domains ---
search_domains=$(scutil --dns | awk -F': ' '/search domain\[[0-9]+\]/ {print $2}' | sort -u)
sd=$(echo "$search_domains" | tr '\n' ',' | sed 's/,$//; s/,/ • /g')
if [[ -n "$sd" ]]; then
  echo "${menu_search_domains} : $sd | refresh=true"
  echo "---"
fi
echo "${menu_ipv6}"
[[ -n "$pub_ip6" ]] && echo "${menu_pub_ipv6} : $pub_ip6 | refresh=true"
# --- Local interface addresses ---
for ifc in $(networksetup -listallhardwareports | awk '/Device: / {print $2}' | sort); do
  ip6_lines=$(ifconfig "$ifc" 2>/dev/null | awk '
    /inet6 / && !/fe80/ {
      split($0, a, " ");
      addr=a[2];
      gsub(/%.*/, "", addr);
      role="";
      if (addr ~ /^fd/) role="ULA";
      else if (index($0, "temporary") || index($0, "TEMPORARY")) role="temporary";
      else if (index($0, "secured") || index($0, "SECURED")) role="secured";
      else if (addr ~ /^fd/) role="ULA";
      else if (index($0, "dynamic")) role="dynamic";
      printf("%s (%s)\n", addr, role=="" ? "none" : role);
    }
  ')
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -n "$line" ]] && echo "${menu_ipv6} ($ifc) : $line | refresh=true"
  done <<< "$ip6_lines"
done
[[ -n "$ts_ip6"  ]] && echo "${menu_ipv6} (Tailscale) : $ts_ip6 | refresh=true"
[[ -n "$dns6"    ]] && echo "${menu_dns_ipv6} : $dns6 | refresh=true"
[[ -n "$gw6"     ]] && echo "${menu_gateway_ipv6} : $gw6 | refresh=true"
[[ -n "$hostname6" ]] && echo "${menu_host_ipv6} : $hostname6 | refresh=true"
echo "---"
echo "${menu_ipv4}"
[[ -n "$pub_ip4" ]] && echo "${menu_pub_ipv4} : $pub_ip4 | refresh=true"
for ifc in $(networksetup -listallhardwareports | awk '/Device: / {print $2}' | sort); do
  ip4=$(ipconfig getifaddr "$ifc" 2>/dev/null)
  [[ -n "$ip4" ]] && echo "${menu_ipv4} ($ifc) : $ip4 | refresh=true"
done
[[ -n "$ts_ip4"  ]] && echo "${menu_ipv4} (Tailscale) : $ts_ip4 | refresh=true"
[[ -n "$dns4"    ]] && echo "${menu_dns_ipv4} : $dns4 | refresh=true"
[[ -n "$gw4"     ]] && echo "${menu_gateway_ipv4} : $gw4 | refresh=true"
[[ -n "$hostname4" ]] && echo "${menu_host_ipv4} : $hostname4 | refresh=true"

# --- Wi-Fi information ---
ssid=$(ipconfig getsummary en0 | awk -F ' SSID : ' '/ SSID : / {print $2}')
if [[ -n "$ssid" ]]; then
  echo "---"
  sp_info=$(system_profiler SPAirPortDataType 2>/dev/null)
  phy=$(echo "$sp_info" | awk -F': ' '/PHY Mode:/{print $2; exit}')
  case "$phy" in
    "802.11a") wifi_ver="Wi-Fi 1" ;;
    "802.11b") wifi_ver="Wi-Fi 2" ;;
    "802.11g") wifi_ver="Wi-Fi 3" ;;
    "802.11n") wifi_ver="Wi-Fi 4" ;;
    "802.11ac") wifi_ver="Wi-Fi 5" ;;
    "802.11ax") wifi_ver="Wi-Fi 6" ;;
    *) wifi_ver="$phy" ;;
  esac
  echo "${menu_wifi} : $ssid • $wifi_ver ($phy) | refresh=true"
fi

# --- Tailscale status ---
if command -v tailscale &>/dev/null; then
  # Machine tags
  ts_tags=$(echo "$ts_json" | jq -r '.Self.Tags // empty | join(", ")')
  # Online status
  ts_online=$(echo "$ts_json" | jq -r '.Self.Online // false')
  # Show DERP section only when connected
  if [[ "$ts_online" != "true" ]]; then
    skip_derp=true
  fi
  # Extract IPv4 and IPv6 addresses
  ts_ip4=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]? | select(test(":") | not)' | head -n1)
  ts_ip6=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]? | select(test(":"))' | head -n1)
  # Remove any scope suffix from Tailscale IPv6
  ts_ip6=${ts_ip6%%\%*}
  # Exit node option
  ts_exit_node=$(echo "$ts_json" | jq -r '.Self.ExitNodeOption // empty')
  # Actual exit node used
  exit_node_id=$(echo "$ts_json" | jq -r '.ExitNodeStatus.ID // empty')
  if [[ -n "$exit_node_id" ]]; then
    exit_node_used=$(echo "$ts_json" \
      | jq -r --arg id "$exit_node_id" \
        '.Peer[] | select(.ID == $id) | .HostName // empty')
  fi

  # Extract the Tailscale IP of the active exit node (if any)
  if [[ -n "$exit_node_id" && -n "$ts_json" ]]; then
    active_exit_ip=$(echo "$ts_json" | jq -r --arg id "$exit_node_id" '.Peer[] | select(.ID == $id) | .TailscaleIPs[]? | select(test(":") | not)')
  fi

  echo "---"
  echo "${menu_tailscale}"
  if [[ "${skip_derp:-}" != true ]]; then
    # Map DERP relay to ISO country code
    derp_to_iso() {
      case "$1" in
        PAR) echo "FR";;
        AMS) echo "NL";;
        FRA) echo "DE";;
        LHR) echo "GB";;
        NRT) echo "JP";;
        SIN) echo "SG";;
        SYD) echo "AU";;
        HKG) echo "HK";;
        IAD|SEA|SFO|SJC|CHI) echo "US";;
        YVR|YYZ) echo "CA";;
        BRL) echo "BR";;
        DUB) echo "IE";;
        *) echo "$1";;
      esac
    }

    # --- Relay used ---
    self_relay=$(echo "$ts_json" | jq -r '.Self.Relay // empty')
    if [[ -n "$self_relay" ]]; then
      rc_upper=$(echo "$self_relay" | tr '[:lower:]' '[:upper:]')
      iso=$(derp_to_iso "$rc_upper")
      # Build flag emoji for ISO code
      relay_flag=""
      for ((i=0; i<${#iso}; i++)); do
        c=${iso:i:1}
        ord=$(printf '%d' "'$c")
        code=$((127397 + ord))
        relay_flag+=$(perl -CO -e "print chr($code)")
      done
      echo "${menu_derp} : ${rc_upper} ${relay_flag} | refresh=true"
    fi
  fi

# --- Tailscale pairs in text mode ---
ts_status=$(tailscale status 2>/dev/null)
if [[ -n "$ts_status" ]]; then
  echo "${menu_pairs}"
  echo "$ts_status" | awk -v active_exit_ip="$active_exit_ip" '
    NF > 4 {
      ip=$1; name=$2; user=$3; os=$4; status="";
      for(i=5;i<=NF;++i) status=status" "$i;
      gsub(/^ /, "", status);
      icon="";
      exiticon="";
      offlineicon="";
      opts="";
      if (status ~ /direct/) icon="􀄭 ";
      # Show open door if this IP is the current exit node in use, else closed door if it offers an exit node
      if (ip == active_exit_ip && status ~ /exit node/) {
        exiticon="􁏜 ";
      } else if (status ~ /offers exit node/) {
        exiticon="􁏝 ";
      }
      if (status ~ /offline/) offlineicon="􀇿 ";
      if (status ~ /offline/ || status ~ /idle/) opts=""; else opts=" | refresh=true";
      if (status != "-")
        print "--" offlineicon exiticon icon name " [" ip "] | href=https://login.tailscale.com/admin/machines/" ip opts;
    }
  '
fi
  [[ -n "$ts_tags" ]] && echo "${menu_tags} : $ts_tags | refresh=true"
  [[ -n "$ts_exit_node" && "$ts_exit_node" != "none" ]] && echo "${menu_ts_exit_config} : $ts_exit_node | refresh=true"
  [[ -n "$exit_node_used" ]] && echo "${menu_ts_exit_active} : $exit_node_used | refresh=true"
  [[ -n "$ts_ip4" ]] && echo "${menu_ts_admin} | href=https://login.tailscale.com/admin/machines/$ts_ip4 refresh=true"

fi
