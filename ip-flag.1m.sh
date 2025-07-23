
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

##### Section: Language Detection #####
# Detect the system language in order to provide bilingual menu labels and descriptions.
# This determines whether the menu appears in French or English.
lang=$(defaults read -g AppleLanguages | awk -F'"' 'NR==2{print $2}' | cut -d'-' -f1)

##### Section: DNS Test Domains #####
# List of domains to use for DNS latency and testing.
dns_test_domains=(cloudflare.com google.com microsoft.com amazon.com)

# Map resolver name to test IP for dig latency checks using flexible pattern matching (regex/case).
resolver_test_ip() {
  case "$1" in
    *[Cc]loudflare*|*1.1.1.1*|*1.0.0.1*)
      echo "1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001"
      ;;
    *[Qq]uad9*|*9.9.9.9*|*149.112.112.112*)
      echo "9.9.9.9 149.112.112.112 2620:fe::fe 2620:fe::9"
      ;;
    *[Gg]oogle*|*8.8.8.8*|*8.8.4.4*)
      echo "8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844"
      ;;
    *[Oo]pendns*|*208.67.222.222*|*208.67.220.220*)
      echo "208.67.222.222 208.67.220.220 2620:119:35::35 2620:119:53::53"
      ;;
    *[Aa]dguard*|*94.140.14.14*|*94.140.15.15*)
      echo "94.140.14.14 94.140.15.15 2a10:50c0::ad1:ff 2a10:50c0::ad2:ff"
      ;;
    *[Ff]reenom*|*80.80.80.80*|*80.80.81.81*)
      echo "80.80.80.80 80.80.81.81 2a02:4780:bad:10::6 2a02:4780:bad:10::7"
      ;;
    *[Yy]andex*|*77.88.8.8*|*77.88.8.1*)
      echo "77.88.8.8 77.88.8.1 2a02:6b8::feed:0ff 2a02:6b8:0:1::feed:0ff"
      ;;
    *[Nn]extdns*|*45.90.28.*|*45.90.30.*|*2a07:a8c*)
      echo "45.90.28.0 45.90.30.0 2a07:a8c0:: 2a07:a8c1::"
      ;;
    *)
      echo ""
      ;;
  esac
}

##### Section: Menu Label Definitions #####
# Define menu labels and other user-facing strings in both French and English, based on the detected system language.
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
    menu_pub_ipv4="Publique"
    menu_pub_ipv6="Publique"
    menu_dns_ipv4="DNS"
    menu_dns_ipv6="DNS"
    menu_gateway_ipv4="Passerelle"
    menu_gateway_ipv6="Passerelle"
    menu_host_ipv4="Hôte"
    menu_host_ipv6="Hôte"
    menu_tags="Tags"
    menu_wifi="Wi-Fi"
    menu_search_domains="Domaines"
    menu_derp="DERP"
    menu_tailscale="Tailscale"
    menu_pairs="→ Pairs"
    menu_ts_exit_config="Exit node configuré"
    menu_ts_exit_active="Exit node"
    menu_ts_admin="→ Ouvrir dans la console d'administration Tailscale"
    menu_host_name="Nom d'hôte"
    nextdns_devices_label="→ Appareils"
    unidentified_device_label="Non identifiés"
    routes_label="Routes"
    show_in_tailscale_console_label="Afficher dans la console Tailscale"
    queries_label="requêtes"
    blocked_label="bloquées"
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
    menu_pub_ipv4="Public"
    menu_pub_ipv6="Public"
    menu_dns_ipv4="DNS"
    menu_dns_ipv6="DNS"
    menu_gateway_ipv4="Gateway"
    menu_gateway_ipv6="Gateway"
    menu_host_ipv4="Host"
    menu_host_ipv6="Host"
    menu_tags="Tags"
    menu_wifi="Wi-Fi"
    menu_search_domains="Search domains"
    menu_derp="DERP"
    menu_tailscale="Tailscale"
    menu_pairs="→ Pairs"
    menu_ts_exit_config="Exit node configured"
    menu_ts_exit_active="Exit node"
    menu_ts_admin="→ Open in Tailscale Admin Console"
    menu_host_name="Host name"
    nextdns_devices_label="→ Devices"
    unidentified_device_label="Unidentified"
    routes_label="Routes"
    show_in_tailscale_console_label="Show in Tailscale Admin Console"
    queries_label="queries"
    blocked_label="blocked"
    ;;
esac

##### Section: Cloudflare Datacenter Mapping #####
# Map Cloudflare datacenter codes to ISO country codes for proper flag display.
cf_colo_to_iso() {
  case "$1" in
    AMS) echo "NL" ;;
    ARN) echo "SE" ;;
    ATL) echo "US" ;;
    BKK) echo "TH" ;;
    CDG) echo "FR" ;;
    CPH) echo "DK" ;;
    DFW) echo "US" ;;
    FRA) echo "DE" ;;
    GIG) echo "BR" ;;
    GRU) echo "BR" ;;
    HKG) echo "HK" ;;
    IAD) echo "US" ;;
    JNB) echo "ZA" ;;
    LAX) echo "US" ;;
    LHR) echo "GB" ;;
    MAD) echo "ES" ;;
    MIA) echo "US" ;;
    NRT) echo "JP" ;;
    ORD) echo "US" ;;
    SEA) echo "US" ;;
    SIN) echo "SG" ;;
    SJC) echo "US" ;;
    SYD) echo "AU" ;;
    VIE) echo "AT" ;;
    YUL) echo "CA" ;;
    YYZ) echo "CA" ;;
    *) echo "" ;;
  esac
}

##### Section: Number Formatting #####
# Format numbers according to the user's locale.
# French uses a space every 3 digits; English uses commas as thousand separators.
format_number() {
  n="$1"
  if [[ "$lang" == "fr" ]]; then
    # Use sed to insert a plain ASCII space every 3 digits from the right for French
    echo "$n" | rev | sed 's/\(...\)/\1 /g' | rev | sed 's/^ *//;s/ *$//'
  else
    # Use sed to insert a comma every 3 digits from the right for English
    echo "$n" | rev | sed 's/\(...\)/\1,/g' | rev | sed 's/^,*//;s/,*$//'
  fi
}

##### Section: External IP Information Fetch #####
# Fetch external IPv4 and IPv6 information using the ifconfig.co JSON API.
# If both requests fail, display an error icon and exit.
json4=$(curl -L -4 -s -H "Accept: application/json" http://ip.rslt.fr/json)
json6=$(curl -L -6 -s -H "Accept: application/json" http://ip.rslt.fr/json)
if [[ -z "$json4" && -z "$json6" ]]; then
  echo "􁣡"
  echo "---"
  echo "Erreur: impossible de récupérer les infos IP | refresh=true"
  exit 1
fi

#
# Use IPv4 JSON if available, otherwise fall back to IPv6 JSON.
json="${json6:-$json4}"

#
# Parse relevant fields from the JSON response for display in the menu.
country_iso=$(jq -r '.country_iso' <<<"$json")
country=$(jq -r '.country // empty' <<<"$json")
asn_org=$(jq -r '.asn_org' <<<"$json")
asn=$(jq -r '.asn' <<<"$json")
city=$(jq -r '.city // empty' <<<"$json")
tz=$(jq -r '.time_zone // empty' <<<"$json")
country_eu=$(jq -r '.country_eu // empty' <<<"$json")

#
# Parse public IPv4 and IPv6 addresses from the respective JSON responses.
# Remove any interface scope from IPv6 addresses and ensure only valid IPv6 addresses are used.
pub_ip4=$(jq -r '.ip // empty' <<< "$json4")
pub_ip6=$(jq -r '.ip // empty' <<< "$json6")
# Remove any scope suffix from public IPv6
pub_ip6=${pub_ip6%%\%*}
# Ignore non-IPv6 results (fallback to IPv4)
if [[ -n "$pub_ip6" && "$pub_ip6" != *:* ]]; then pub_ip6=""; fi

# Join PTR hostnames for display in SwiftBar (avoid Unicode paste issues)
ptrs4=$(dig -x "$pub_ip4" +short | awk 'NF')
hostname4=""
for p in $ptrs4; do
  [[ -n "$hostname4" ]] && hostname4+=" • "
  hostname4+="${p%.}"
done

ptrs6=$(dig -x "$pub_ip6" +short | awk 'NF')
hostname6=""
for p in $ptrs6; do
  [[ -n "$hostname6" ]] && hostname6+=" • "
  hostname6+="${p%.}"
done

##### Section: Local Interface and Address Detection #####
# Determine the default network interface and fetch the local IPv4 address for that interface.
iface=$(route get default 2>/dev/null | awk '/interface:/ {print $2}')
local_ip4=$(ipconfig getifaddr "$iface" 2>/dev/null || echo "")
#
# Fetch the local IPv6 address on the same interface as the default IPv4.
# Only use global (not link-local) addresses.
local_ip6=$(ifconfig "$iface" 2>/dev/null \
  | awk '/inet6 / && !/fe80/ {print $2; exit}' \
  | sed 's/%.*//')
ip6="$local_ip6"

##### Section: Flag Emoji Construction #####
# Build a flag emoji from the ISO country code by converting each letter to a regional indicator symbol.
flag=""
for ((i=0; i<${#country_iso}; i++)); do
  c=${country_iso:i:1}
  ord=$(printf '%d' "'$c")
  reg=$((ord + 127397))
  flag+=$(perl -CO -e "print chr($reg)")
done

##### Section: Network Icon Selection #####
# Set the default network icon. If a Tailscale exit node is in use, display a special icon.
network_icon="􀤆"
if command -v tailscale &>/dev/null; then
  ts_status_json=$(tailscale status --json 2>/dev/null)
  exit_node_in_use=$(echo "$ts_status_json" | jq -r '.ExitNodeStatus.Online // false')
  if [[ "$exit_node_in_use" == "true" ]]; then
    network_icon="􁅏"
  fi
fi

##### Section: ASN Organization Name Mapping #####
# Map known ASN organizations to more readable short names for display in the menu.
case "$asn_org" in
  "Free SAS") asn_org_f="Free" ;;
  "Free Pro SAS") asn_org_f="Free Pro" ;;
  "Free Mobile SAS") asn_org_f="Free Mobile" ;;
  "OVH SAS") asn_org_f="OVH" ;;
  "Societe Francaise Du Radiotelephone - SFR SA") asn_org_f="SFR" ;;
  "ZAYO-6461") asn_org_f="Zayo" ;;
  "Iguane Solutions SAS"|"IGUANA-WORLDWIDE") asn_org_f="IG1" ;;
  "VNPT Corp"|"VIETNAM POSTS AND TELECOMMUNICATIONS GROUP") asn_org_f="VNPT" ;;
  "AKAMAI-AS") asn_org_f="Akamai" ;;
  "CLOUDFLARENET") asn_org_f="Cloudflare" ;;
  "Assistance Publique Hopitaux De Paris") asn_org_f="APHP" ;;
  "Kaopu Cloud HK Limited") asn_org_f="Kaopu Cloud" ;;
  "Digital Storage Company Limited") asn_org_f="123HOST" ;;
  *) asn_org_f="$asn_org" ;;
esac

##### Section: ISP Icon Fetch and Encoding #####
# Attempt to fetch the ISP's icon from a static URL. If unavailable, fall back to the domain's favicon.
# Encode the image as base64 for display in the menu.
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

##### Section: Main Menu Output #####
# Output the main menu bar icon, ISP name, and ASN information with clickable links.
# Also display city, country (with flag), and time zone.
echo "${network_icon}  ${asn_org_f}"
echo "---"
# Only display the image if it is set and is long enough to be a valid image (avoid empty lines when logo is missing)
if [[ -n "$image_enc" && "${#image_enc}" -gt 100 ]]; then
  echo "| image=${image_enc}"
  echo "---"
fi

#
# Show ASN operator name and clickable AS numbers, handling cases where IPv4 and IPv6 ASNs differ.
asn4=$(jq -r '.asn // empty' <<<"$json4")
asn6=$(jq -r '.asn // empty' <<<"$json6")
if [[ -n "$asn4" && -n "$asn6" ]]; then
  if [[ "$asn4" == "$asn6" ]]; then
    echo "${asn_org} • $asn4 | href=https://radar.cloudflare.com/$asn4 refresh=true"
  else
    echo "${asn_org} • $asn6 • $asn4 | href=https://radar.cloudflare.com/$asn6 refresh=true"
  fi
elif [[ -n "$asn4" ]]; then
  echo "${asn_org} • $asn4 | href=https://radar.cloudflare.com/$asn4 refresh=true"
elif [[ -n "$asn6" ]]; then
  echo "${asn_org} • $asn6 | href=https://radar.cloudflare.com/$asn6 refresh=true"
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
#
# If city or country is available, provide a menu entry to open the location in Apple Maps.
if [[ -n "$city" || -n "$country" ]]; then
  query=$(printf '%s %s' "$city" "$country" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/ /%20/g')
  echo "${menu_open_in_maps} | href=maps://?q=${query} refresh=true"
fi

##### Section: DNS Server Detection #####
# Fetch DNS servers used by the default interface, separating IPv4 and IPv6.
# Remove any interface scope. If none found, fall back to all system DNS servers.
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

#
# Fallback: if no DNS found for the interface, show all DNS servers on the system.
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

#
# Get the default IPv4 and IPv6 gateways for the system, removing any interface scope from IPv6.
gw4=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
gw6=$(route -n get -inet6 default 2>/dev/null | awk '/gateway:/ {print $2}')
# Remove any scope suffix from IPv6 gateway
gw6=${gw6%%\%*}

echo "---"
##### Section: Tailscale Status Detection #####
# If Tailscale is installed, get its status and online state using a single JSON call.
if command -v tailscale &>/dev/null; then
  ts_json=$(tailscale status --json --peers 2>/dev/null)
  ts_online=$(echo "$ts_json" | jq -r '.Self.Online // false')
else
  ts_json=""
  ts_online="false"
fi

##### Section: General Network Information #####
# Build a section with general network information, including host name and search domains.
# Also, fetch and display DNS resolver info (e.g., NextDNS) if available.
network_lines=()
[[ -n "$(hostname)" ]] && network_lines+=("${menu_host_name} : $(hostname) | refresh=true")
#
# Get search domains in use and display as a single line.
search_domains=$(scutil --dns | awk -F': ' '/search domain\[[0-9]+\]/ {print $2}' | sort -u)
sd=$(echo "$search_domains" | tr '\n' ',' | sed 's/,$//; s/,/ • /g')
if [[ -n "$sd" ]]; then
  network_lines+=("${menu_search_domains} : $sd | refresh=true")
fi

#
#
# Fetch DNS resolver (e.g., NextDNS) information and format label for display.

# Try NextDNS detection first
resolver_name=""
resolver_label=""
nextdns_test_json=$(curl -L -sL --max-time 2 https://test.nextdns.io/)
nextdns_status=$(echo "$nextdns_test_json" | jq -r '.status // empty')
if [[ "$nextdns_status" == "ok" ]]; then
  resolver_name="NextDNS"
  resolver_proto=$(echo "$nextdns_test_json" | jq -r '.protocol // empty')
  resolver_server=$(echo "$nextdns_test_json" | jq -r '.server // empty')
  # Extract location code from server (e.g. netbarista-par-1 → PAR)
  if [[ "$resolver_server" =~ -([a-z]{3})-([0-9]+)$ ]]; then
    cf_colo="${BASH_REMATCH[1]}"
    cf_colo_upper=$(echo "$cf_colo" | tr '[:lower:]' '[:upper:]')
    cf_iso=$(cf_colo_to_iso "$cf_colo_upper")
    resolver_flag=""
    if [[ -n "$cf_iso" ]]; then
      for ((i=0; i<${#cf_iso}; i++)); do
        c=${cf_iso:i:1}
        ord=$(printf '%d' "'$c")
        code=$((127397 + ord))
        resolver_flag+=$(perl -CO -e "print chr($code)")
      done
    fi
    resolver_display="$resolver_name • $resolver_proto • $resolver_server"
    if [[ -n "$resolver_flag" ]]; then
      resolver_display+=" $resolver_flag"
    fi
  else
    resolver_display="$resolver_name • $resolver_proto • $resolver_server"
  fi
  # Measure DNS latency for the resolver: try ICMP ping, fallback to DNS query latency via system resolver
  resolver_ip="$resolver_server"
  if [[ "$resolver_name" == "NextDNS" ]]; then
    resolver_ip=$(echo "$nextdns_test_json" | jq -r '.destIP // empty')
  fi

  dns_latency=""
  # Try ICMP ping first
  if ping -c 2 -W 1 "$resolver_ip" &>/dev/null; then
    dns_latency=$(ping -c 2 -q "$resolver_ip" | awk -F'/' '/^rtt/ {print int($5)}')
  fi
  # If ping fails, fallback to DNS query latency via resolver_test_ip or system resolver (minimum latency logic)
  if [[ -z "$dns_latency" ]]; then
    dns_latency=""
    min_latency=""
    test_ips=( $(resolver_test_ip "$resolver_name") )
    if [[ ${#test_ips[@]} -gt 0 ]]; then
      for ip in "${test_ips[@]}"; do
        for domain in "${dns_test_domains[@]}"; do
          latency=$(dig @"$ip" "$domain" +stats +timeout=1 2>/dev/null | awk -F': ' '/Query time/ {print $2}' | awk '{print $1}')
          if [[ -n "$latency" ]]; then
            if [[ -z "$min_latency" || "$latency" -lt "$min_latency" ]]; then
              min_latency="$latency"
            fi
          fi
        done
      done
    else
      for domain in "${dns_test_domains[@]}"; do
        latency=$(dig "$domain" +stats +timeout=1 2>/dev/null | awk -F': ' '/Query time/ {print $2}' | awk '{print $1}')
        if [[ -n "$latency" ]]; then
          if [[ -z "$min_latency" || "$latency" -lt "$min_latency" ]]; then
            min_latency="$latency"
          fi
        fi
      done
    fi
    dns_latency="$min_latency"
  fi
  dns_latency_avg=""
  if [[ -n "$dns_latency" ]]; then
    dns_latency_avg="${dns_latency} ms"
  fi
  case "$lang" in
    fr) resolver_label="DNS : $resolver_display | refresh=true" ;;
    *)  resolver_label="DNS: $resolver_display | refresh=true" ;;
  esac
  if [[ -n "$dns_latency_avg" ]]; then
    resolver_display+=" • $dns_latency_avg"
    resolver_label="${resolver_label%| refresh=true} • $dns_latency_avg | refresh=true"
  fi
else
  # Fallback to old resolver detection (Cloudflare etc), use ping for latency, fallback to dig if ping fails
  resolver_ip=$(curl -L -sL --max-time 2 https://test.nextdns.io/ | jq -r '.resolver // empty')
  if [[ -n "$resolver_ip" ]]; then
    resolver_name=$(curl -L -sL --max-time 2 "https://api.nextdns.io/resolver/${resolver_ip}" | jq -r '.name // empty')
  fi
  dns_latency=""
  dns_latency_label=""
  # Try ICMP ping first
  dns_latency=""
  min_latency=""
  test_ips=( $(resolver_test_ip "$resolver_name") )
  if [[ ${#test_ips[@]} -gt 0 ]]; then
    for ip in "${test_ips[@]}"; do
      for domain in "${dns_test_domains[@]}"; do
        latency=$(dig @"$ip" "$domain" +stats +timeout=1 2>/dev/null | awk -F': ' '/Query time/ {print $2}' | awk '{print $1}')
        if [[ -n "$latency" ]]; then
          if [[ -z "$min_latency" || "$latency" -lt "$min_latency" ]]; then
            min_latency="$latency"
          fi
        fi
      done
    done
  else
    for domain in "${dns_test_domains[@]}"; do
      latency=$(dig "$domain" +stats +timeout=1 2>/dev/null | awk -F': ' '/Query time/ {print $2}' | awk '{print $1}')
      if [[ -n "$latency" ]]; then
        if [[ -z "$min_latency" || "$latency" -lt "$min_latency" ]]; then
          min_latency="$latency"
        fi
      fi
    done
  fi
  dns_latency="$min_latency"
  if [[ -z "$dns_latency" ]]; then
    # If all dig attempts failed, fallback to ping
    if ping -c 2 -W 1 "$resolver_ip" &>/dev/null; then
      dns_latency=$(ping -c 2 -q "$resolver_ip" | awk -F'/' '/^rtt/ {print int($5)}')
      dns_latency_label="Ping"
    fi
  fi
  dns_latency_avg=""
  if [[ -n "$dns_latency" ]]; then
    dns_latency_avg="${dns_latency} ms"
  fi
  # If resolver_name is Cloudflare, get colo and flag
  if [[ -n "$resolver_name" && "$resolver_name" != "null" ]]; then
    resolver_flag=""
    resolver_info="$resolver_name"
    # if [[ "$resolver_name" == "Cloudflare" ]]; then
    #   cf_trace=$(curl -L -sL --max-time 2 https://one.one.one.one/cdn-cgi/trace)
    #   cf_colo=$(echo "$cf_trace" | grep '^colo=' | awk -F= '{print $2}')
    #   if [[ -n "$cf_colo" ]]; then
    #     cf_iso=$(cf_colo_to_iso "$cf_colo")
    #     for ((i=0; i<${#cf_iso}; i++)); do
    #       c=${cf_iso:i:1}
    #       ord=$(printf '%d' "'$c")
    #       code=$((127397 + ord))
    #       resolver_flag+=$(perl -CO -e "print chr($code)")
    #     done
    #     resolver_info+=" • $cf_colo${resolver_flag:+ $resolver_flag}"
    #   fi
    # else
      # For other resolvers: fetch city and country via ip.rslt.fr/json and build flag.
    dns_info_json=$(curl -sL "https://ip.rslt.fr/json?ip=$resolver_ip")
    dns_country_iso=$(echo "$dns_info_json" | jq -r '.country_iso // empty')
    dns_city=$(echo "$dns_info_json" | jq -r '.city // empty')
    resolver_flag=""
    if [[ ${#dns_country_iso} -eq 2 ]]; then
      for ((i=0; i<${#dns_country_iso}; i++)); do
        c=${dns_country_iso:i:1}
        ord=$(printf '%d' "'$c")
        code=$((127397 + ord))
        resolver_flag+=$(perl -CO -e "print chr($code)")
      done
    fi
    # resolver_info="${resolver_info}"
    if [[ -n "$dns_city" ]]; then
      resolver_info="${resolver_info} • $dns_city"
    fi
    if [[ -n "$resolver_flag" ]]; then
      resolver_info="${resolver_info} $resolver_flag"
    fi
  fi
  if [[ -n "$dns_latency_avg" ]]; then
    resolver_info+=" • $dns_latency_avg"
  fi
  case "$lang" in
    fr) resolver_label="DNS : $resolver_info | refresh=true" ;;
    *)  resolver_label="DNS: $resolver_info | refresh=true" ;;
  esac
  # fi
fi
# Insert the resolver_label into the network_lines array at the correct position as before.

if [[ -n "$resolver_label" ]]; then
  # Always append the DNS latency to the resolver_label if not already present
  if [[ -n "$resolver_label" && -n "$dns_latency_avg" && "$resolver_label" != *"$dns_latency_avg"* ]]; then
    resolver_label="${resolver_label%| refresh=true} • $dns_latency_avg | refresh=true"
  fi
  if [[ -n "$sd" ]]; then
    network_lines+=("$resolver_label")
    if [[ ${#network_lines[@]} -ge 2 ]]; then
      tmp=("${network_lines[@]:0:2}" "$resolver_label" "${network_lines[@]:2:${#network_lines[@]}-2-1}")
      network_lines=("${tmp[@]}")
    fi
  else
    network_lines+=("$resolver_label")
    if [[ ${#network_lines[@]} -ge 1 ]]; then
      tmp=("${network_lines[@]:0:1}" "$resolver_label" "${network_lines[@]:1:${#network_lines[@]}-1-1}")
      network_lines=("${tmp[@]}")
    fi
  fi
fi

if [[ ${#network_lines[@]} -gt 0 ]]; then
  echo "${menu_network}"
  printf "%s\n" "${network_lines[@]}"
  echo "---"
fi

##### Section: IPv6 Information Output #####
# IPv6 section: collect and display all relevant IPv6 addresses, DNS, gateways, and hostnames.
# Also, enumerate all interfaces and their global IPv6 addresses.
ipv6_lines=()
[[ -n "$pub_ip6" ]] && ipv6_lines+=("${menu_pub_ipv6} : $pub_ip6 | refresh=true")
for ifc in $(networksetup -listallhardwareports | awk '/Device: / {print $2}' | sort); do
  if6s=$(ifconfig "$ifc" 2>/dev/null | awk -v lang="$lang" '
    /inet6 / && !/fe80/ {
      addr=$2; gsub(/%.*/, "", addr);
      role="";
      if (addr ~ /^fd/) role=(lang=="fr"?"ULA":"ULA");
      else if (index($0, "temporary") || index($0, "TEMPORARY"))
        role=(lang=="fr"?"Temporaire":"Temporary");
      else if (index($0, "secured") || index($0, "SECURED"))
        role=(lang=="fr"?"Sécurisée":"Secured");
      else if (index($0, "dynamic"))
        role=(lang=="fr"?"Dynamique":"Dynamic");
      else role=(lang=="fr"?"Publique":"Public");
      printf("%s • %s : %s\n", "'$ifc'", role, addr);
    }
  ')
  while IFS= read -r line; do
    [[ -n "$line" ]] && ipv6_lines+=("$line | refresh=true")
  done <<< "$if6s"
done
[[ -n "$dns6"    ]] && ipv6_lines+=("${menu_dns_ipv6} : $dns6 | refresh=true")
[[ -n "$gw6"     ]] && ipv6_lines+=("${menu_gateway_ipv6} : $gw6 | refresh=true")
[[ -n "$hostname6" ]] && ipv6_lines+=("${menu_host_ipv6} : $hostname6 | refresh=true")
if [[ ${#ipv6_lines[@]} -gt 0 ]]; then
  echo "${menu_ipv6}"
  printf "%s\n" "${ipv6_lines[@]}"
  echo "---"
fi

##### Section: IPv4 Information Output #####
# IPv4 section: collect and display public and local IPv4 addresses, DNS, gateways, and hostnames.
# Enumerate all interfaces and show their IPv4 addresses.
ipv4_lines=()
[[ -n "$pub_ip4" ]] && ipv4_lines+=("${menu_pub_ipv4} : $pub_ip4 | refresh=true")
for ifc in $(networksetup -listallhardwareports | awk '/Device: / {print $2}' | sort); do
  ip4=$(ipconfig getifaddr "$ifc" 2>/dev/null)
  [[ -n "$ip4" ]] && ipv4_lines+=("$ifc : $ip4 | refresh=true")
done
[[ -n "$dns4"    ]] && ipv4_lines+=("${menu_dns_ipv4} : $dns4 | refresh=true")
[[ -n "$gw4"     ]] && ipv4_lines+=("${menu_gateway_ipv4} : $gw4 | refresh=true")
[[ -n "$hostname4" ]] && ipv4_lines+=("${menu_host_ipv4} : $hostname4 | refresh=true")
if [[ ${#ipv4_lines[@]} -gt 0 ]]; then
  echo "${menu_ipv4}"
  printf "%s\n" "${ipv4_lines[@]}"
fi

##### Section: Wi-Fi Information Output #####
# Wi-Fi section: display current SSID, Wi-Fi version, frequency, channel, bandwidth, signal strength, transmit rate, and security, each on its own line (after SSID/PHY).
# Signal and speed are extracted using the 'airport' tool and system_profiler.
ssid=$(ipconfig getsummary en0 | awk -F ' SSID : ' '/ SSID : / {print $2}')
if [[ -n "$ssid" ]]; then
  sp_info=$(system_profiler SPAirPortDataType 2>/dev/null)
  sp_info=$(echo "$sp_info" | awk '/Other Local Wi-Fi Networks:/ {exit} {print}')
  # Extract Country Code from main block (not Current Network Information)
  wifi_country_code=$(echo "$sp_info" | awk -F'Country Code: ' '/Country Code: / {print $2; exit}')
  # Generate flag from country code
  wifi_country_flag=""
  if [[ -n "$wifi_country_code" && ${#wifi_country_code} -eq 2 ]]; then
    upper_code=$(echo "$wifi_country_code" | tr '[:lower:]' '[:upper:]')
    for ((i=0; i<${#upper_code}; i++)); do
      c=${upper_code:i:1}
      ord=$(printf '%d' "'$c")
      code=$((127397 + ord))
      wifi_country_flag+=$(perl -CO -e "print chr($code)")
    done
  fi
  phy=$(echo "$sp_info" | awk -F': ' '/PHY Mode:/{print $2; exit}')
  # Map 802.11 PHY modes to Wi-Fi generation labels (including Wi-Fi 8 / 802.11bn)
  case "$phy" in
    "802.11a") wifi_ver="Wi-Fi 1" ;;
    "802.11b") wifi_ver="Wi-Fi 2" ;;
    "802.11g") wifi_ver="Wi-Fi 3" ;;
    "802.11n") wifi_ver="Wi-Fi 4" ;;
    "802.11ac") wifi_ver="Wi-Fi 5" ;;
    "802.11ax") wifi_ver="Wi-Fi 6" ;;
    "802.11be") wifi_ver="Wi-Fi 7" ;;
    "802.11bn") wifi_ver="Wi-Fi 8" ;;
    *) wifi_ver="$phy" ;;
  esac
  # Extract channel, bandwidth, frequency, signal, transmit rate, security from system_profiler
  wifi_channel_line=$(echo "$sp_info" | awk -F'Channel: ' '/Channel: / {print $2; exit}')
  wifi_channel_num=$(echo "$wifi_channel_line" | awk '{print $1}')
  wifi_bandwidth=$(echo "$wifi_channel_line" | grep -o '[0-9]\+MHz')
  wifi_channel=$(echo "$wifi_channel_line" | awk '{print $1}')
  # Frequency label
  wifi_freq_label_sp=""
  if [[ -n "$wifi_channel" ]]; then
    if (( wifi_channel >= 1 && wifi_channel <= 14 )); then
      wifi_freq_label_sp="2,4 GHz"
    elif (( wifi_channel >= 36 && wifi_channel <= 165 )); then
      wifi_freq_label_sp="5 GHz"
    elif (( wifi_channel > 165 )); then
      wifi_freq_label_sp="6 GHz"
    else
      wifi_freq_label_sp="?"
    fi
  fi
  # Signal (dBm), Noise (dBm), and transmit rate
  wifi_signal_noise_line=$(echo "$sp_info" | awk -F'Signal / Noise: ' '/Signal \/ Noise:/ {print $2; exit}')
  wifi_signal=$(echo "$wifi_signal_noise_line" | awk '{print $1}')
  wifi_noise=$(echo "$wifi_signal_noise_line" | awk -F'/' '{if (NF > 1) print $2}' | awk '{print $1}')
  wifi_txrate_sp=$(echo "$sp_info" | awk -F'Transmit Rate: ' '/Transmit Rate:/ {print $2; exit}' | grep -Eo '[0-9]+')
  # Security
  wifi_security=$(echo "$sp_info" | awk '/Current Network Information:/,0' | awk -F'Security: ' '/Security: / {print $2; exit}')

  echo "---"

  # Calculate SNR and Wi-Fi quality icon
  wifi_quality_stars=""
  if [[ -n "$wifi_signal" && -n "$wifi_noise" && "$wifi_signal" =~ ^-?[0-9]+$ && "$wifi_noise" =~ ^-?[0-9]+$ ]]; then
    wifi_snr=$((wifi_signal - wifi_noise))
    if (( wifi_snr >= 10 )); then
      wifi_quality_stars="􀙇"
    else
      wifi_quality_stars="􀙥"
    fi
  fi

  echo "${menu_wifi}"

  # First line: SSID • Wi-Fi X (802.11xx) • Frequency (if present)
  wifi_line="${wifi_quality_stars} ${ssid} • $wifi_ver ($phy)"
  if [[ -n "$wifi_freq_label_sp" ]]; then
    wifi_line+=" • $wifi_freq_label_sp"
  fi
  echo "${wifi_line} | refresh=true"
  # Sub-lines: Channel, Bandwidth, Signal, Transmit rate, Security
  # Channel and Bandwidth together
  case "$lang" in
    fr) channel_label="Canal" ;;
    *)  channel_label="Channel" ;;
  esac
  channel_and_bw="$wifi_channel_num"
  if [[ -n "$wifi_channel_num" && -n "$wifi_bandwidth" ]]; then
    channel_and_bw+=" • $wifi_bandwidth"
  elif [[ -n "$wifi_bandwidth" ]]; then
    channel_and_bw="$wifi_bandwidth"
  fi
  if [[ -n "$wifi_country_flag" ]]; then
    channel_and_bw+=" $wifi_country_flag"
  fi
  if [[ -n "$channel_and_bw" ]]; then
    printf "%s : %s | refresh=true\n" "$channel_label" "$channel_and_bw"
  fi
  # Signal
  case "$lang" in
    fr) sig_label="Signal" ; noise_label="Bruit" ;;
    *)  sig_label="Signal" ; noise_label="Noise" ;;
  esac
  if [[ -n "$wifi_signal" ]]; then
    printf "%s : %s dBm | refresh=true\n" "$sig_label" "$wifi_signal"
  fi
  # Noise
  if [[ -n "$wifi_noise" ]]; then
    printf "%s : %s dBm | refresh=true\n" "$noise_label" "$wifi_noise"
  fi
  # Transmit rate (convert to Gbps if >=1000, locale-aware)
  case "$lang" in
    fr) rate_label="Débit" ;;
    *)  rate_label="Transmit rate" ;;
  esac
  # Only show transmit rate if strictly greater than zero
  if [[ -n "$wifi_txrate_sp" && "$wifi_txrate_sp" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    if (( $(awk "BEGIN {print ($wifi_txrate_sp > 0)}") )); then
      if (( $(awk "BEGIN {print ($wifi_txrate_sp >= 1000)}") )); then
        val=$(awk "BEGIN {printf \"%.1f\", $wifi_txrate_sp/1000}")
        if [[ "$lang" == "fr" ]]; then
          val=$(echo "$val" | sed 's/\./,/')
          unit="Gbit/s"
        else
          unit="Gbps"
        fi
        printf "%s : %s %s | refresh=true\n" "$rate_label" "$val" "$unit"
      else
        val=$(awk "BEGIN {printf \"%d\", $wifi_txrate_sp}")
        if [[ "$lang" == "fr" ]]; then
          unit="Mbit/s"
        else
          unit="Mbps"
        fi
        printf "%s : %s %s | refresh=true\n" "$rate_label" "$val" "$unit"
      fi
    fi
  fi
  # Security
  case "$lang" in
    fr) sec_label="Sécurité" ;;
    *)  sec_label="Security" ;;
  esac
  if [[ -n "$wifi_security" ]]; then
    printf "%s : %s | refresh=true\n" "$sec_label" "$wifi_security"
  fi
fi

##### Section: Tailscale Peer Information Output #####
# If Tailscale is online, display Tailscale-specific information, including DERP relay, machine tags, and all Tailscale peers.
# For each peer, display connection status, OS, tags, last seen, and relay location.
# Also, show routes and handle online/offline status for each peer.
if [[ "$ts_online" == "true" ]]; then
  # Nearest DERP and its latency
  nearest_derp=""
  derp_latency=""
  if command -v tailscale &>/dev/null; then
    nearest_derp=$(tailscale netcheck 2>/dev/null | awk -F': ' '/Nearest DERP:/ {print $2}' | xargs)
    if [[ -n "$nearest_derp" ]]; then
      derp_latency=$(tailscale netcheck 2>/dev/null | awk -v city="$nearest_derp" '
        $0 ~ "- " && $0 ~ city {
          match($0, /: *([0-9.]+)ms/, a)
          if (a[1] != "") print a[1]
        }
      ')
    fi
  fi

  ts_lines=()
  # Machine tags
  ts_tags=$(echo "$ts_json" | jq -r '.Self.Tags // empty | join(", ")')
  # Online status already checked
  # Show DERP section only when connected
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

  [[ -n "$ts_ip6"  ]] && ts_lines+=("${menu_ipv6} : $ts_ip6 | refresh=true")
  [[ -n "$ts_ip4"  ]] && ts_lines+=("${menu_ipv4} : $ts_ip4 | refresh=true")
  #
  # Map DERP relay code to ISO country code for flag display.
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

  #
  # If a DERP relay is used, display its code, country flag, city, and latency if available.
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

    # Parse DERP city and latency for display with DERP info
    derp_city=""
    derp_latency=""
    if [[ -n "$rc_upper" ]]; then
      lower_rc_upper=$(echo "$rc_upper" | tr '[:upper:]' '[:lower:]')
      derp_line=$(tailscale netcheck 2>/dev/null | awk -v code="$lower_rc_upper" '
        $0 ~ "- " && $0 ~ ("- " code ":") {print}
      ')
      if [[ -n "$derp_line" ]]; then
        derp_latency=$(echo "$derp_line" | sed -nE 's/.*: *([0-9.]+)ms.*/\1/p')
        derp_city=$(echo "$derp_line" | awk -F'[()]' '{gsub(/^[ \t-]+/, "", $2); print $2}')
      fi
    fi

    derp_info="${menu_derp} : ${rc_upper} ${relay_flag}"
    # New conditional for DERP display with city/latency
    if [[ -n "$derp_city" ]]; then
      if [[ -n "$derp_latency" ]]; then
        derp_info+=" (${derp_city} • ${derp_latency} ms)"
      else
        derp_info+=" (${derp_city})"
      fi
    fi
    ts_lines+=("$derp_info | refresh=true")
  fi

  #
  # List all Tailscale peers (machines) with their status, OS, tags, and relay info.
  # Avoid duplicates and handle both online and offline peers.
  ts_status=$(tailscale status 2>/dev/null)
  ts_peers_online=()
  ts_peers_offline=()
  pairs_seen=""
  # Get all the IPs of the local Tailscale node (Self)
  self_ips=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]?')
  if [[ -n "$ts_status" ]]; then
    while IFS= read -r ts_line; do
      # Skip header or empty lines
      [[ "$ts_line" =~ ^100\. ]] || continue
      ip=$(echo "$ts_line" | awk '{print $1}')
      name=$(echo "$ts_line" | awk '{print $2}')
      [[ -z "$ip" || -z "$name" ]] && continue
      key="${ip}|${name}"
      # Skip if already displayed
      [[ "$pairs_seen" == *"|$key|"* ]] && continue
      pairs_seen="${pairs_seen}|$key|"
      # Determine if the IP corresponds to Self
      is_self=0
      for self_ip in $self_ips; do
        if [[ "$ip" == "$self_ip" ]]; then
          is_self=1
          break
        fi
      done

      if [[ "$is_self" == "1" ]]; then
        os=$(echo "$ts_json" | jq -r '.Self.OS // empty')
        tags=$(echo "$ts_json" | jq -r '[.Self.Tags[]? | sub("^tag:";"")] | join(" • ")')
        last_seen_fmt=""
      else
        peer_json=$(echo "$ts_json" | jq -c --arg ip "$ip" '.Peer[] | select(.TailscaleIPs[]? == $ip)')
        os=$(echo "$peer_json" | jq -r '.OS // empty')
        tags=$(echo "$peer_json" | jq -r '[.Tags[]? | sub("^tag:";"")] | join(" • ")')
        last_seen=$(echo "$peer_json" | jq -r '.LastSeen // empty')
        if [[ "$last_seen" == "0001-01-01T00:00:00Z" || -z "$last_seen" ]]; then
          last_seen_fmt=""
        else
          if [[ "$lang" == "fr" ]]; then
            last_seen_fmt=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${last_seen:0:19}" "+%d/%m/%Y %H:%M" 2>/dev/null)
          else
            last_seen_fmt=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${last_seen:0:19}" "+%Y-%m-%d %H:%M" 2>/dev/null)
          fi
          [[ -z "$last_seen_fmt" ]] && last_seen_fmt="$last_seen"
        fi
      fi
      # Status text
      status_txt=$(echo "$ts_line" | awk '{for(i=5;i<=NF;++i) printf $i" "; print ""}' | sed 's/[ ,]*$//')
      icon=""
      exiticon=""
      offlineicon=""
      relayicon=""
      opts=""
      if [[ "$status_txt" == *direct* ]]; then icon="   􀄭 "; fi
      if [[ "$status_txt" == *"offers exit node"* ]]; then exiticon="􁏝 "; fi
      if [[ "$status_txt" == *"exit node"* && "$ip" == "$active_exit_ip" ]]; then exiticon="􁏜 "; fi
      if [[ "$status_txt" == *offline* ]]; then offlineicon="􁣡 "; fi
      if [[ "$status_txt" == *'relay "'* ]]; then relayicon="   􀅌 "; fi
      if [[ "$status_txt" != "-" && "$status_txt" != *offline* && "$status_txt" != *idle* ]]; then opts=" | refresh=true"; fi

      # Extract direct/relay info from status_txt for display
      direct_info=""
      if [[ "$status_txt" == *'relay "'* ]]; then
        # Extract relay code from status_txt, e.g., relay "sin"
        if [[ "$status_txt" =~ relay\ \"([a-zA-Z0-9_-]+)\" ]]; then
          relay_code="${BASH_REMATCH[1]}"
          direct_info="$(echo "$relay_code" | tr '[:lower:]' '[:upper:]')"
        fi
      elif [[ "$status_txt" == *direct* ]]; then
        # Match both IPv4 and IPv6 (in brackets) addresses with port
        # IPv4: direct 1.2.3.4:1234
        # IPv6: direct [abcd:abcd:...]:1234
        if [[ "$status_txt" =~ direct[[:space:]]\[([0-9a-fA-F:]+)\]:([0-9]+) ]]; then
          # IPv6 with brackets
          direct_ip="${BASH_REMATCH[1]}"
          direct_port="${BASH_REMATCH[2]}"
          direct_info="${direct_ip}:${direct_port}"
        elif [[ "$status_txt" =~ direct[[:space:]]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+) ]]; then
          # IPv4
          direct_ip="${BASH_REMATCH[1]}"
          direct_port="${BASH_REMATCH[2]}"
          direct_info="${direct_ip}:${direct_port}"
        fi
      fi
      # Peer line (name/IP + icons)
      if [[ "$is_self" == "1" ]]; then
        peer_display_name="--􀉩 ${offlineicon}${exiticon}${name}${icon}${relayicon}${direct_info}$opts | href=https://login.tailscale.com/admin/machines/$ip"
      else
        peer_display_name="--${offlineicon}${exiticon}${name}${icon}${relayicon}${direct_info}$opts | href=https://login.tailscale.com/admin/machines/$ip"
      fi
      peer_lines=("$peer_display_name")

      # Add IPv4 address as subline
      peer_lines+=("----${ip} | refresh=true")
      # Extract IPv6 Tailscale address for this peer (if any)
      if [[ "$is_self" == "1" ]]; then
        peer_ipv6=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]? | select(test(":"))' | head -n1)
      else
        peer_ipv6=$(echo "$peer_json" | jq -r '.TailscaleIPs[]? | select(test(":"))' | head -n1)
      fi
      peer_ipv6=${peer_ipv6%%\%*}
      if [[ -n "$peer_ipv6" ]]; then
        peer_lines+=("----$peer_ipv6 | refresh=true")
      fi
      # Only print the FQDN (DNSName) ONCE, after all IPs
      if [[ "$is_self" == "1" ]]; then
        fqdn=$(echo "$ts_json" | jq -r '.Self.DNSName // empty')
      else
        fqdn=$(echo "$peer_json" | jq -r '.DNSName // empty')
      fi
      if [[ -n "$fqdn" && "$fqdn" != "null" ]]; then
        fqdn_stripped=${fqdn%.}
        peer_lines+=("----$fqdn_stripped | refresh=true")
      fi
      # If routes are present for this machine, display them as a submenu under the peer.
      if [[ "$is_self" == "1" ]]; then
        routes=$(echo "$ts_json" | jq -r '.Self.PrimaryRoutes[]?' 2>/dev/null)
      else
        routes=$(echo "$peer_json" | jq -r '.PrimaryRoutes[]?' 2>/dev/null)
      fi

      if [[ -n "$routes" ]]; then
        route_lines=("-------" "----${routes_label}")
        while IFS= read -r route; do
          [[ -n "$route" ]] && route_lines+=("----$route | refresh=true")
        done <<< "$routes"
        peer_lines+=("${route_lines[@]}")
      fi

      peer_lines+=("-------" "----${show_in_tailscale_console_label} | href=https://login.tailscale.com/admin/machines/$ip")

      # Display last seen date, OS, and tags in a single line below the peer name.
      fused="--"
      [[ -n "$last_seen_fmt" ]] && fused+="􀋭 $last_seen_fmt"
      # Set the OS icon
      os_icon="􀪬"
      os_lower=$(echo "$os" | tr '[:upper:]' '[:lower:]')
      os_name=$os
      # If the device name contains "ipad" (case-insensitive), override OS icon/name
      if [[ "$name" =~ [Ii][Pp][Aa][Dd] ]]; then
        os_icon="􀟠"
        os_name="iPadOS"
      else
        case "$os_lower" in
          windows*) os_icon="􀥺" ; os_name="Windows" ;;
          macos*) os_icon="􁈸" ; os_name="macOS" ;;
          ios*) os_icon="􀟜" ; os_name="iOS" ;;
          tvos*) os_icon="􀎲" ; os_name="tvOS" ;;
          android*) os_icon="􁤫" ; os_name="Android" ;;
          linux*) os_icon="􀧘" ; os_name="Linux" ;;
          *) os_icon="􀪬" ;;
        esac
      fi
      os_display=$(echo "$os_name" | xargs)
      [[ -n "$os_display" && "$os_display" != "null" ]] && fused+="   $os_icon $os_display"
      [[ -n "$tags" && "$tags" != "null" ]] && fused+="   􀋡 $tags"
      # Insert the owner if peer has no tags, just after tags and before DERP/relay
      user_id_pair=""
      if [[ "$is_self" == "1" ]]; then
        user_id_pair=$(echo "$ts_json" | jq -r '.Self.UserID // empty')
      else
        user_id_pair=$(echo "$peer_json" | jq -r '.UserID // empty')
      fi
      # Only show owner if there are no tags (real user)
      tags_empty=0
      if [[ -z "$tags" || "$tags" == "null" ]]; then tags_empty=1; fi
      if [[ "$tags_empty" == "1" && -n "$user_id_pair" ]]; then
        display_name=$(echo "$ts_json" | jq -r --arg uid "$user_id_pair" '.User[$uid].DisplayName // empty')
        if [[ -n "$display_name" ]]; then
          fused+="   􀉩 $display_name"
        fi
      fi
      # If relay field is present, add relay code and flag to the display line.
      if [[ "$is_self" == "1" ]]; then
        relay_val=$(echo "$ts_json" | jq -r '.Self.Relay // empty')
      else
        relay_val=$(echo "$peer_json" | jq -r '.Relay // empty')
      fi
      if [[ -n "$relay_val" && "$relay_val" != "null" ]]; then
        rc_upper=$(echo "$relay_val" | tr '[:lower:]' '[:upper:]')
        # Use function to map DERP code to ISO country code (defined above)
        iso=$(derp_to_iso "$rc_upper")
        # Generate the flag for the country
        relay_flag=""
        for ((i=0; i<${#iso}; i++)); do
          c=${iso:i:1}
          ord=$(printf '%d' "'$c")
          code=$((127397 + ord))
          relay_flag+=$(perl -CO -e "print chr($code)")
        done
        fused+="   􀋑 $rc_upper $relay_flag"
      fi
      if [[ "$fused" != "--" ]]; then
        fused+=" | size=10"
        peer_lines+=("$fused")
      fi

      # Add the peer to the online or offline list based on its status text.
      if [[ "$status_txt" == *offline* || "$status_txt" == *idle* ]]; then
        ts_peers_offline+=("${peer_lines[@]}")
      else
        ts_peers_online+=("${peer_lines[@]}")
      fi
    done <<< "$ts_status"
  fi

  # Output: display online peers first, then offline peers, under the Tailscale section.
  if [[ ${#ts_peers_online[@]} -gt 0 || ${#ts_peers_offline[@]} -gt 0 ]]; then
    ts_lines+=("${menu_pairs}")
    for peer_line in "${ts_peers_online[@]}"; do
      ts_lines+=("$peer_line")
    done
    for peer_line in "${ts_peers_offline[@]}"; do
      ts_lines+=("$peer_line")
    done
  fi
  if [[ ${#ts_lines[@]} -gt 0 ]]; then
    echo "---"
    echo "${menu_tailscale}"
    printf "%s\n" "${ts_lines[@]}"
  fi
fi

##### Section: NextDNS API Analytics Output #####
# Fetch and display DNS statistics and analytics using the NextDNS API.
# This includes global and per-device stats, top contacted/blocked domains, GAFAM breakdown, and country breakdown.

#
# Define NextDNS menu labels and icons depending on language.
case "$lang" in
  fr)
    nextdns_menu="NextDNS"
    global_stats_title="Statistiques globales"
    device_stats_title="Ce Mac"
    period_labels=("􀀒" "􀀖" "􀀜")
    ;;
  *)
    nextdns_menu="NextDNS"
    global_stats_title="Global statistics"
    device_stats_title="This Mac"
    period_labels=("􀀒" "􀀊" "􀀜")
    ;;
esac

#
# Calculate the relevant time periods for statistics: last hour, today, and this month.
# These are used to query the NextDNS API for analytics.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
this_hour=$(date -u +%Y-%m-%dT%H:00:00Z)
last_hour=$(date -u -v -1H +%Y-%m-%dT%H:00:00Z)
today=$(date -u +%Y-%m-%dT00:00:00Z)
month_start=$(date -u +%Y-%m-01T00:00:00Z)

periods_from=("$last_hour" "$today" "$month_start")
periods_to=("$now" "$now" "$now")

if [[ -n "$NEXTDNS_API_KEY" && -n "$NEXTDNS_PROFILE_ID" ]]; then
  echo "---"

  #
  # Test the NextDNS connection and show the server and protocol in use.
  nextdns_test_json=$(curl -L --max-time 2 https://test.nextdns.io/)
  test_status=$(jq -r '.status // empty' <<<"$nextdns_test_json")
  if [[ "$test_status" == "ok" ]]; then
    proto=$(jq -r '.protocol // empty' <<<"$nextdns_test_json")
    server=$(jq -r '.server // empty' <<<"$nextdns_test_json")
    echo "$nextdns_menu • ${NEXTDNS_PROFILE_ID} • $server • $proto"
  else
    echo "$nextdns_menu • ${NEXTDNS_PROFILE_ID} 􀇾"
  fi

  #
  # For each period (last hour, today, this month), fetch and display the total and blocked DNS queries.
  for i in "${!periods_from[@]}"; do
    label="${period_labels[$i]}"
    from="${periods_from[$i]}"
    to="${periods_to[$i]}"
    json=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" \
      "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/status?from=$from&to=$to")
    total=$(jq '[.data[] | select(.status=="default")][0].queries // 0' <<<"$json")
    blocked=$(jq '[.data[] | select(.status=="blocked")][0].queries // 0' <<<"$json")
    pct="0"
    if [[ "$total" != "0" && "$total" != "" ]]; then
      pct=$(awk "BEGIN {printf \"%.1f\", 100*$blocked/$total}")
    fi
    echo "$label $(format_number $total) ${queries_label} • $(format_number $blocked) ${blocked_label} • $pct% | refresh=true"
  done

  #
  # Add year-to-date statistics.
  case "$lang" in
    fr) year_label="􀀄" ;;
    *)  year_label="􀀴" ;;
  esac
  from=$(date -u -v-1y +%Y-%m-%dT%H:%M:%SZ)
  to="$now"
  json_year=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" \
    "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/status?from=$from&to=$to")
  total=$(jq '[.data[] | select(.status=="default")][0].queries // 0' <<<"$json_year")
  blocked=$(jq '[.data[] | select(.status=="blocked")][0].queries // 0' <<<"$json_year")
  pct="0"
  if [[ "$total" != "0" && "$total" != "" ]]; then
    pct=$(awk "BEGIN {printf \"%.1f\", 100*$blocked/$total}")
  fi
  echo "$year_label $(format_number $total) ${queries_label} • $(format_number $blocked) ${blocked_label} • $pct% | refresh=true"

  # Display all-time (no time limit) NextDNS statistics.
  json_alltime=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" \
    "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/status")
  total=$(jq '[.data[] | select(.status=="default")][0].queries // 0' <<<"$json_alltime")
  blocked=$(jq '[.data[] | select(.status=="blocked")][0].queries // 0' <<<"$json_alltime")
  pct="0"
  if [[ "$total" != "0" && "$total" != "" ]]; then
    pct=$(awk "BEGIN {printf \"%.1f\", 100*$blocked/$total}")
  fi
  echo "􀵏 $(format_number $total) ${queries_label} • $(format_number $blocked) ${blocked_label} • $pct% | refresh=true"

  #
  # Show top 20 contacted and blocked domains as submenus.
  if [[ "$lang" == "fr" ]]; then
    domains_label="→ Domaines les plus contactés"
    blocked_domains_label="→ Domaines les plus bloqués"
  else
    domains_label="→ Most contacted domains"
    blocked_domains_label="→ Most blocked domains"
  fi

  # Function to fetch and print a domain list (contacted or blocked).
  print_domains() {
    url="$1"
    submenulabel="$2"
    cursor=""
    count=0
    echo "$submenulabel"
    while true; do
      fullurl="$url"
      [[ -n "$cursor" ]] && fullurl="${url}&cursor=${cursor}"
    domains_json=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" "$fullurl")
      for row in $(jq -c '.data[]' <<<"$domains_json"); do
        domain=$(jq -r '.domain' <<<"$row")
        queries=$(jq -r '.queries' <<<"$row")
        queries_fmt=$(format_number "$queries")
        count=$((count+1))
        # Limit to 20 domains
        [[ $count -le 20 ]] && echo "--$domain • $queries_fmt  | refresh=true" || break 2
      done
      # Pagination: check for cursor
      cursor=$(jq -r '.meta.pagination.cursor // empty' <<<"$domains_json")
      [[ -z "$cursor" || $count -ge 20 ]] && break
    done
  }

  print_domains "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/domains" "$domains_label"
  print_domains "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/domains?status=blocked" "$blocked_domains_label"

  #
  # GAFAM requests breakdown submenu: show the percentage of queries to major tech companies.
  gafam_json=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/destinations?type=gafam")
  gafam_total=$(jq '[.data[].queries] | add' <<<"$gafam_json")
  if [[ "$lang" == "fr" ]]; then
    gafam_label="→ GAMAM 􀺧"
  else
    gafam_label="→ GAMAM 􀺧"
  fi
  if [[ "$gafam_total" != "0" && "$gafam_total" != "" ]]; then
    echo "$gafam_label"
    for row in $(jq -c '.data[]' <<<"$gafam_json"); do
      company=$(jq -r '.company' <<<"$row")
      queries=$(jq -r '.queries' <<<"$row")
      pct=$(awk "BEGIN {printf \"%.1f\", 100*$queries/$gafam_total}")
      # Map company code to readable label.
      case "$company" in
        apple) name="Apple" ;;
        microsoft) name="Microsoft" ;;
        google) name="Google" ;;
        facebook) name="Meta" ;;
        amazon) name="Amazon" ;;
        others) name="$([[ "$lang" == "fr" ]] && echo "Autres" || echo "Others")" ;;
        *) name="$company" ;;
      esac
      echo "--$name • $pct% | refresh=true"
    done
  fi

  #
  # Countries breakdown submenu: show percentage of queries by country, with flag and top domains as submenus.
  # Collect all country data via pagination to ensure accuracy.
  all_countries_json=""
  cursor=""
  while true; do
    fullurl="https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/destinations?type=countries"
    [[ -n "$cursor" ]] && fullurl="${fullurl}&cursor=${cursor}"
    page_json=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" "$fullurl")
    all_countries_json="${all_countries_json}$(jq -c '.data[]' <<<"$page_json")"$'\n'
    cursor=$(jq -r '.meta.pagination.cursor // empty' <<<"$page_json")
    [[ -z "$cursor" ]] && break
  done
  country_total=$(echo "$all_countries_json" | jq -s '[.[].queries] | add')
  if [[ "$lang" == "fr" ]]; then
    countries_label="→ Pays 􀵳"
  else
    countries_label="→ Countries 􀵳"
  fi
  if [[ "$country_total" != "0" && "$country_total" != "" ]]; then
    echo "$countries_label"
    countries_seen=""
    while IFS= read -r row; do
      [[ -z "$row" ]] && continue
      code=$(jq -r '.code' <<<"$row")
      name=$(jq -r '.name' <<<"$row")
      key="${code}_${name}"
      if [[ "$countries_seen" == *"|$key|"* ]]; then
        continue
      fi
      countries_seen="${countries_seen}|$key|"
      queries=$(jq -r '.queries' <<<"$row")
      if [[ -n "$country_total" && "$country_total" != "0" && -n "$queries" && "$queries" != "0" ]]; then
        pct=$(LC_NUMERIC=C awk "BEGIN {printf \"%.1f\", 100*$queries/$country_total}")
        # Build flag emoji for country code.
        flag=""
        if [[ ${#code} -eq 2 ]]; then
          upper_code=$(echo "$code" | tr '[:lower:]' '[:upper:]')
          c1=${upper_code:0:1}
          c2=${upper_code:1:1}
          flag=$(python3 -c "print(chr(0x1F1E6 + (ord('$c1') - 65)) + chr(0x1F1E6 + (ord('$c2') - 65)))")
        fi
        rounded_pct=$(awk "BEGIN {printf \"%.1f\", $pct}")
        if [[ -n "$name" && -n "$code" ]]; then
          if [[ $(awk "BEGIN {print ($rounded_pct >= 0.1)}") -eq 1 ]]; then
            echo "--$flag $name • $rounded_pct% | refresh=true"
          else
            echo "--$flag $name • < 0.1% | refresh=true"
          fi
        fi
        # Show top domains for this country as submenu.
        domains_json=$(jq -r '.domains // empty' <<<"$row")
        if [[ "$domains_json" != "null" && -n "$domains_json" ]]; then
          count_domains=0
          echo "$domains_json" | jq -r '.[]' | head -n20 | while read -r domain; do
            count_domains=$((count_domains+1))
            echo "----$domain | refresh=true"
          done
        fi
      fi
    done <<< "$all_countries_json"
  fi

  # (Commented out) NextDNS Devices breakdown submenu: show top 10 devices by percentage of queries.
  # devices_json=$(curl -s -H "X-Api-Key: $NEXTDNS_API_KEY" "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/devices")
  # # Sort by .queries descending and take top 10
  # top_devices_arr=$(echo "$devices_json" | jq '[.data[]] | sort_by(-.queries) | .[:10]')
  # # Calculate the sum of queries for the top 10 devices
  # devices_top10_total=$(echo "$top_devices_arr" | jq '[.[].queries] | add')
  # if [[ -n "$top_devices_arr" && "$devices_top10_total" != "0" && "$devices_top10_total" != "" ]]; then
  #   echo "$nextdns_devices_label"
  #   echo "$top_devices_arr" | jq -c '.[]' | while IFS= read -r dev; do
  #     id=$(echo "$dev" | jq -r '.id')
  #     name=$(echo "$dev" | jq -r '.name // empty')
  #     queries=$(echo "$dev" | jq -r '.queries')
  #     model=$(echo "$dev" | jq -r '.model // empty')
  #     # Use label for unidentified
  #     if [[ "$id" == "__UNIDENTIFIED__" || -z "$name" || "$name" == "null" ]]; then
  #       name="$unidentified_device_label"
  #     fi
  #     # Calculate percentage of queries for this device out of the top 10
  #     pct=$(awk "BEGIN {printf \"%.1f\", 100*$queries/$devices_top10_total}")
  #     if [[ "$pct" == "0.0" ]]; then
  #       echo "--$name • < 0.1% | refresh=true"
  #     else
  #       echo "--$name • $pct% | refresh=true"
  #     fi
  #     if [[ -n "$model" && "$model" != "null" ]]; then
  #       echo "----$model | refresh=true"
  #     fi
  #   done
  # fi

  # (Commented out) NextDNS Protocols breakdown (top 10 protocols by percentage)
  # protocols_json=$(curl -s -H "X-Api-Key: $NEXTDNS_API_KEY" "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/protocols")
  # top_protocols_arr=$(echo "$protocols_json" | jq '[.data[]] | sort_by(-.queries) | .[:10]')
  # # Calculate the sum of queries for the top 10 protocols
  # protocols_top10_total=$(echo "$top_protocols_arr" | jq '[.[].queries] | add')
  # if [[ "$lang" == "fr" ]]; then
  #   protocols_label="→ Protocoles"
  # else
  #   protocols_label="→ Protocols"
  # fi
  # if [[ -n "$top_protocols_arr" && "$protocols_top10_total" != "0" && "$protocols_top10_total" != "" ]]; then
  #   echo "$protocols_label"
  #   echo "$top_protocols_arr" | jq -c '.[]' | while IFS= read -r proto; do
  #     proto_name=$(echo "$proto" | jq -r '.protocol')
  #     queries=$(echo "$proto" | jq -r '.queries')
  #     # Calculate percentage of queries for this protocol out of the top 10
  #     pct=$(awk "BEGIN {printf \"%.1f\", 100*$queries/$protocols_top10_total}")
  #     if [[ "$pct" == "0.0" ]]; then
  #       echo "--$proto_name • < 0.1% | refresh=true"
  #     else
  #       echo "--$proto_name • $pct% | refresh=true"
  #     fi
  #   done
  # fi

  # NextDNS Query Types breakdown (top 10 query types by percentage)
  querytypes_json=$(curl -L -s -H "X-Api-Key: $NEXTDNS_API_KEY" "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/queryTypes")
  top_querytypes_arr=$(echo "$querytypes_json" | jq '[.data[]] | sort_by(-.queries) | .[:10]')
  # Calculate the sum of queries for the top 10 query types
  querytypes_top10_total=$(echo "$top_querytypes_arr" | jq '[.[].queries] | add')
  if [[ "$lang" == "fr" ]]; then
    querytypes_label="→ Types de requêtes"
  else
    querytypes_label="→ Query types"
  fi
  if [[ -n "$top_querytypes_arr" && "$querytypes_top10_total" != "0" && "$querytypes_top10_total" != "" ]]; then
    echo "$querytypes_label"
    echo "$top_querytypes_arr" | jq -c '.[]' | while IFS= read -r qt; do
      type_name=$(echo "$qt" | jq -r '.name')
      queries=$(echo "$qt" | jq -r '.queries')
      # Calculate percentage of queries for this query type out of the top 10
      pct=$(awk "BEGIN {printf \"%.1f\", 100*$queries/$querytypes_top10_total}")
      if [[ "$pct" == "0.0" ]]; then
        echo "--$type_name • < 0.1% | refresh=true"
      else
        echo "--$type_name • $pct% | refresh=true"
      fi
    done
  fi
fi
