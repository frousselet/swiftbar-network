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


script_dir="$(cd "$(dirname "$0")" && pwd)"

# --- helpers & caches ---------------------------------------------------------

# Build a flag emoji from a 2-letter ISO country code (e.g., FR → 🇫🇷).
flag_from_iso() {
  local iso="$1"
  [[ -z "$iso" || ${#iso} -ne 2 ]] && { echo ""; return; }
  local upper_code; upper_code=$(echo "$iso" | tr '[:lower:]' '[:upper:]')
  local out="" c ord code
  for ((i=0; i<${#upper_code}; i++)); do
    c=${upper_code:i:1}
    ord=$(printf '%d' "'$c")
    code=$((127397 + ord))
    out+=$(perl -CO -e "print chr($code)")
  done
  echo "$out"
}

# Simple helpers to validate IP formats
is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}
is_ipv6() {
  local ip="$1"
  [[ "$ip" == *:* ]]
}

#
# Cache directory for JSON and other files.
CACHEDIR="${HOME}/.cache/swiftbar-network-info"
mkdir -p "$CACHEDIR"


# ensure_icon_size: center-crop to square and resize to NxN (best-effort)
ensure_icon_size() {
  local f="$1" size="${2:-16}" tmp="${f}.tmp"
  [[ ! -s "$f" ]] && return 1
  if command -v magick >/dev/null 2>&1; then
    magick "$f" -alpha on -background none \
      -thumbnail ${size}x${size}^ -gravity center -extent ${size}x${size} \
      -unsharp 1x1+1.2+0.02 -strip "$tmp" >/dev/null 2>&1 && mv "$tmp" "$f" && return 0
  elif command -v convert >/dev/null 2>&1; then
    convert "$f" -alpha on -background none \
      -thumbnail ${size}x${size}^ -gravity center -extent ${size}x${size} \
      -unsharp 1x1+1.2+0.02 -strip "$tmp" >/dev/null 2>&1 && mv "$tmp" "$f" && return 0
  elif command -v sips >/dev/null 2>&1; then
    sips -z "$size" "$size" "$f" >/dev/null 2>&1 && return 0
  fi
  return 1
}

#
# cache_url: unified caching for json|image|binary
# Usage:
#   cache_url json   "<url>" <ttl> [ext]            [ignored] [follow]
#   cache_url image  "<url>" <ttl> [ext] [size]      [follow]
#   cache_url binary "<url>" <ttl> [ext]             [ignored] [follow]
#   follow: "nofollow" or "0" to disable -L; anything else (or empty) follows redirects.
# Returns:
#   json  -> prints JSON content to stdout
#   image -> prints cached file path
#   binary-> prints cached file path
cache_url() {
  local kind="$1" url="$2" ttl="$3" ext="$4" size="$5" follow="$6"
  local hash cache_file now_ts file_ts age tmp CURLFOLLOW
  [[ -z "$kind" || -z "$url" || -z "$ttl" ]] && { echo ""; return 0; }
  # Redirect policy
  if [[ "$follow" == "0" || "$follow" == "nofollow" || "$follow" == "false" ]]; then
    CURLFOLLOW=""
  else
    CURLFOLLOW="-L"
  fi
  # Normalize kind
  case "$kind" in
    json|JSON) kind="json" ;;
    image|img|IMAGE) kind="image" ;;
    bin|binary|BIN|BINARY) kind="binary" ;;
    *) kind="binary" ;;
  esac
  # Derive extension if needed
  if [[ "$kind" == "json" ]]; then
    ext="json"
  else
    if [[ -z "$ext" ]]; then
      # Always store images as PNG to guarantee SwiftBar compatibility
      ext="png"
    fi
  fi
  # Build cache file name from SHA-256 of the URL
  hash=$(echo -n "$url" | shasum -a 256 | awk '{print $1}')
  cache_file="${CACHEDIR}/${hash}.${ext}"
  # If kind=image and a cache file exists but it is not an image (e.g., HTML), delete it
  if [[ "$kind" == "image" && -s "$cache_file" ]]; then
    if command -v file >/dev/null 2>&1; then
      mime_cached=$(file -b --mime-type "$cache_file")
      if [[ "$mime_cached" != image/* ]]; then
        rm -f "$cache_file" 2>/dev/null
      fi
    fi
  fi
  # If cache exists and is fresh, return
  if [[ -s "$cache_file" ]]; then
    now_ts=$(date +%s)
    file_ts=$(date +%s -r "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null)
    age=$((now_ts - file_ts))
    if (( age < ttl )); then
      if [[ "$kind" == "json" ]]; then
        cat "$cache_file"
      else
        echo "$cache_file"
      fi
      return 0
    fi
  fi
  # Fetch to temp, then commit if non-empty
  tmp="${cache_file}.tmp.$$"
  if [[ "$kind" == "json" ]]; then
    local json
    json=$(curl --max-time 3 -s $CURLFOLLOW "$url")
    # Do not cache HTML as JSON (avoid caching error pages)
    if [[ -n "$json" && "$json" == [{\[]* ]]; then
      echo "$json" > "$cache_file"
      echo "$json"
      return 0
    fi
    [[ -s "$cache_file" ]] && cat "$cache_file" || echo ""
    return 0
  else
    # Download while capturing HTTP status and content type
    meta=$(curl -sS $CURLFOLLOW --max-time 4 -w '%{http_code}|||%{content_type}' -o "$tmp" "$url")
    http_code="${meta%%|||*}"
    content_type="${meta#*|||}"

    if [[ -s "$tmp" ]]; then
      if [[ "$kind" == "image" ]]; then
        # Require a 200 status and an image/* content type to accept the file
        if [[ "$http_code" != "200" || "$content_type" != image/* ]]; then
          rm -f "$tmp" 2>/dev/null
          # Return existing cache if any; otherwise empty to allow caller fallback (e.g., favicon)
          [[ -s "$cache_file" ]] && echo "$cache_file" || echo ""
          return 0
        fi
        # Ensure final cached file is PNG regardless of source format
        local cache_png="${CACHEDIR}/${hash}.png"
        if command -v magick >/dev/null 2>&1; then
          magick "$tmp" -alpha on -background none -strip "$cache_png" >/dev/null 2>&1 || cp "$tmp" "$cache_png"
        elif command -v convert >/dev/null 2>&1; then
          convert "$tmp" -alpha on -background none -strip "$cache_png" >/dev/null 2>&1 || cp "$tmp" "$cache_png"
        elif command -v sips >/dev/null 2>&1; then
          sips -s format png "$tmp" --out "$cache_png" >/dev/null 2>&1 || cp "$tmp" "$cache_png"
        else
          # No converter available; if the file is already PNG, just move it; otherwise leave as-is but rename
          if command -v file >/dev/null 2>&1 && [[ "$(file -b --mime-type "$tmp")" == "image/png" ]]; then
            mv "$tmp" "$cache_png"
          else
            mv "$tmp" "$cache_png"
          fi
        fi
        rm -f "$tmp" 2>/dev/null
        cache_file="$cache_png"
        if [[ -n "$size" ]]; then
          ensure_icon_size "$cache_file" "$size" >/dev/null 2>&1 || true
        fi
        echo "$cache_file"
        return 0
      else
        # Binary path: no content-type restriction
        mv "$tmp" "$cache_file"
        echo "$cache_file"
        return 0
      fi
    fi
    rm -f "$tmp" 2>/dev/null
    [[ -s "$cache_file" ]] && echo "$cache_file" || echo ""
    return 0
  fi
}

# Centralize a few expensive calls so we can reuse their results later.
# (All commands below are best-effort; they must not block SwiftBar for long.)
SPCACHE=""     # system_profiler cache
TSCACHE_JSON=""  # tailscale status --json --peers cache
TSCACHE_NETCHECK=""  # tailscale netcheck cache
NEXTDNS_TEST_JSON="" # https://test.nextdns.io/ cache
CF_LOC_JSON=""   # https://speed.cloudflare.com/locations cache

# Preload system_profiler just once (it can be slow). Limit runtime.
if command -v system_profiler >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    SPCACHE=$(timeout 3s system_profiler SPAirPortDataType 2>/dev/null)
  else
    SPCACHE=$(system_profiler SPAirPortDataType 2>/dev/null)
  fi
fi

# Preload tailscale status/netcheck once, if available.
if command -v tailscale >/dev/null 2>&1; then
  TSCACHE_JSON=$(tailscale status --json --peers 2>/dev/null)
  if command -v timeout >/dev/null 2>&1; then
    TSCACHE_NETCHECK=$(timeout 3s tailscale netcheck 2>/dev/null)
  else
    TSCACHE_NETCHECK=$(tailscale netcheck 2>/dev/null)
  fi
fi

# Cache NextDNS test once (used in two sections further down).
if command -v curl >/dev/null 2>&1; then
  NEXTDNS_TEST_JSON=$(curl -L --max-time 2 -s https://test.nextdns.io/)
fi
# Cache Cloudflare locations (IATA -> ISO country code mapping) for up to 7 days using cache_url.
if command -v curl >/dev/null 2>&1; then
  CF_LOC_MAX_AGE=$((7 * 24 * 3600)) # 7 days
  CF_LOC_JSON=$(cache_url json "https://speed.cloudflare.com/locations" "$CF_LOC_MAX_AGE")
fi
# TTL for ip.rslt.fr/json?ip=... lookups (cache for 24h)
IP_JSON_TTL=$((24 * 3600))  # 24h cache for ip.rslt.fr/json?ip=...
# --- end helpers & caches -----------------------------------------------------

#
# Detect system language for localization of menu labels and values.
# Support French and English. Extract language from AppleLanguages preference.
lang=$(defaults read -g AppleLanguages | awk -F'"' 'NR==2{print $2}' | cut -d'-' -f1)

#
# Define domains for DNS latency measurement and resolution tests.
dns_test_domains=(cloudflare.com google.com microsoft.com amazon.com)

# Map DNS resolver name or IP to test IP addresses for latency checks.
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

#
# Define menu labels, section headers, and user-facing strings in French and English.
# Select the correct set based on detected system language.
case "$lang" in
  fr)
    menu_external_ip="IP Publique"
    menu_city="Ville"
    menu_country="Pays"
    menu_timezone="Fuseau horaire"
    menu_open_in_maps="→ Ouvrir dans Apple Plans 􀙊"
    menu_network="Réseau"
    menu_dns_provider="Fournisseur DNS"
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
    menu_dns_provider="DNS provider"
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

# operator_info_map: return canonical operator name AND canonical domain from a raw org/provider string.
# Output format: "<canon>|<domain>" where <domain> can be empty if unknown.
operator_info_map() {
  local raw="$1"
  case "$raw" in
    "AKAMAI-AS")                                        echo "Akamai|akamai.com" ;;
    "Assistance Publique Hopitaux De Paris")            echo "AP-HP|aphp.fr" ;;
    "CLOUDFLARENET"|"Cloudflare Inc")                    echo "Cloudflare|cloudflare.com" ;;
    "BOUYGTEL-ISP"|"Bouygues Telecom SA")               echo "Bouygues Telecom|bouyguestelecom.fr" ;;
    "CISCO-UMBRELLA")                                   echo "Cisco Umbrella|opendns.com" ;;
    "OpenDNS, LLC")                                     echo "OpenDNS|opendns.com" ;;
    "Free Mobile SAS")                                  echo "Free Mobile|free.fr" ;;
    "Free Pro SAS")                                     echo "Free Pro|free.fr" ;;
    "Free SAS")                                         echo "Free|free.fr" ;;
    "Google DNS"|"Google LLC"|"GOOGLE")                 echo "Google|google.com" ;;
    "IGUANA-WORLDWIDE"|"Iguane Solutions SAS")          echo "Iguane Solutions|iguanesolutions.com" ;;
    "OVH SAS")                                          echo "OVHcloud|ovhcloud.com" ;;
    "Societe Francaise Du Radiotelephone - SFR SA")     echo "SFR|sfr.fr" ;;
    "VNPT Corp"|"VIETNAM POSTS AND TELECOMMUNICATIONS GROUP") echo "VNPT|vnpt.vn" ;;
    "ZAYO-6461")                                        echo "Zayo|zayo.com" ;;
    "NextDNS")                                          echo "NextDNS|nextdns.io" ;;
    "AdGuard"|"Adguard")                                echo "AdGuard|adguard.com" ;;
    "Quad9"|"QUAD9")                                    echo "Quad9|quad9.net" ;;
    *)                                                   echo "${raw}|" ;;
  esac
}

# Map raw ASN organization or DNS provider name to a user-friendly version.
map_operator_name() {
  local raw="$1"
  local info canon
  info="$(operator_info_map "$raw")"
  canon="${info%%|*}"
  echo "$canon"
}

# Resolve a reliable domain for a provider (ISP or DNS) from ASN/org name/IP.
# Order of resolution:
#  1) Canonical mapping table (operator_info_map) on normalized org name (stable domains)
#  2) WHOIS email domain fallback (abuse-mailbox / OrgAbuseEmail / OrgTechEmail)
#  3) Empty if unresolved
provider_domain_for() {
  local asn="$1" org_raw="$2" ip="$3"
  local info canon domain email_domain
  info="$(operator_info_map "$org_raw")"
  canon="${info%%|*}"
  domain="${info#*|}"
  # If the map already provides a domain, use it
  if [[ -n "$domain" && "$domain" != "$canon" ]]; then
    echo "$domain"; return
  fi
  # WHOIS email domain fallback (try multiple common fields)
  if command -v whois >/dev/null 2>&1 && [[ -n "$asn" ]]; then
    local whois_out
    whois_out="$(whois "$asn" 2>/dev/null)"
    if [[ -z "$whois_out" && -n "$ip" ]]; then
      whois_out="$(whois "$ip" 2>/dev/null)"
    fi
    if [[ -n "$whois_out" ]]; then
      email_domain=$(printf "%s" "$whois_out" | awk -F: '/abuse-mailbox|OrgAbuseEmail|OrgTechEmail|org-tech-email|abuse-mail/ {print $2}' | awk '{print $1}' | sed 's/.*@//' | head -n1)
      if [[ -n "$email_domain" ]]; then
        echo "$email_domain"; return
      fi
    fi
  fi
  echo ""
}

#
# Map Cloudflare datacenter codes to ISO 3166-1 alpha-2 country codes using dynamic JSON lookup.
cf_colo_to_iso() {
  # Map Cloudflare colo IATA code to ISO 3166-1 alpha-2 using Cloudflare's public locations feed.
  # Usage: cf_colo_to_iso "CDG" -> "FR". Returns empty string on failure.
  local code="$1"
  [[ -z "$code" ]] && { echo ""; return; }
  # Normalize to uppercase
  code=$(echo "$code" | tr '[:lower:]' '[:upper:]')
  # Prefer cached JSON; jq is already a dependency of this script.
  if [[ -n "$CF_LOC_JSON" ]]; then
    local iso
    iso=$(echo "$CF_LOC_JSON" | jq -r --arg code "$code" '.[] | select(.iata == $code) | .cca2 // empty' 2>/dev/null | head -n1)
    if [[ -n "$iso" && "$iso" != "null" ]]; then
      echo "$iso"
      return
    fi
  fi
  # Fallback: empty if not found or cache unavailable.
  echo ""
}

#
# Format numbers according to user's locale for display in the menu.
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

#
#
# Fetch external IPv4 and IPv6 information from remote API.
json4=$(curl -L --max-time 3 -4 -s -H "Accept: application/json" http://ip.rslt.fr/json)
json6=$(curl -L --max-time 3 -6 -s -H "Accept: application/json" http://ip.rslt.fr/json)
if [[ -z "$json4" && -z "$json6" ]]; then
  echo "􁣡"
  echo "---"
  echo "Error: unable to retrieve IP information | refresh=true"
  exit 1
fi

#
# If Tailscale is installed, obtain status and online state using JSON call.
if command -v tailscale &>/dev/null; then
  ts_json="$TSCACHE_JSON"
  ts_online=$(echo "$ts_json" | jq -r '.Self.Online // false')
  magicdns_enabled=$(echo "$ts_json" | jq -r '.CurrentTailnet.MagicDNSEnabled // false')
  magicdns_org=$(echo "$ts_json" | jq -r '.CurrentTailnet.Name // empty')
  magicdns_domain=$(echo "$ts_json" | jq -r '.CurrentTailnet.MagicDNSSuffix // empty')
else
  ts_json=""
  ts_online="false"
  magicdns_enabled="false"
  magicdns_org=""
  magicdns_domain=""
fi

# Prefer IPv4 JSON if available, otherwise fall back to IPv6 JSON.
json="${json6:-$json4}"

# Parse relevant fields from JSON API response for display.
country_iso=$(jq -r '.country_iso' <<<"$json")
country=$(jq -r '.country // empty' <<<"$json")
asn_org=$(jq -r '.asn_org' <<<"$json")
asn=$(jq -r '.asn' <<<"$json")
city=$(jq -r '.city // empty' <<<"$json")
tz=$(jq -r '.time_zone // empty' <<<"$json")
country_eu=$(jq -r '.country_eu // empty' <<<"$json")

# Parse public IPv4 and IPv6 addresses from JSON responses.
pub_ip4=$(jq -r '.ip // empty' <<< "$json4")
pub_ip6=$(jq -r '.ip // empty' <<< "$json6")
# Remove scope suffix from public IPv6.
pub_ip6=${pub_ip6%%\%*}
# Ignore non-IPv6 results (fallback to IPv4).
if [[ -n "$pub_ip6" && "$pub_ip6" != *:* ]]; then pub_ip6=""; fi


# Perform reverse DNS lookups (PTR) for public IPs.
# Join multiple PTR results with a bullet for display.
hostname4=""
if [[ -n "$pub_ip4" ]] && is_ipv4 "$pub_ip4"; then
  ptrs4=$(dig -x "$pub_ip4" +short | awk 'NF')
  for p in $ptrs4; do
    h="${p%.}"
    # Skip non-standard PTRs (octal escapes like \032, invalid chars, bad labels)
    if [[ "$h" == *\\* ]]; then continue; fi
    if ! [[ "$h" =~ ^[A-Za-z0-9.-]+$ ]]; then continue; fi
    valid=1
    IFS='.' read -ra labels <<< "$h"
    for lbl in "${labels[@]}"; do
      if [[ -z "$lbl" || ${#lbl} -gt 63 ]]; then valid=0; break; fi
      if ! [[ "$lbl" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then valid=0; break; fi
    done
    (( valid )) || continue
    [[ -n "$hostname4" ]] && hostname4+=" • "
    hostname4+="$h"
  done
fi


hostname6=""
if [[ -n "$pub_ip6" ]] && is_ipv6 "$pub_ip6"; then
  ptrs6=$(dig -x "$pub_ip6" +short | awk 'NF')
  for p in $ptrs6; do
    h="${p%.}"
    if [[ "$h" == *\\* ]]; then continue; fi
    if ! [[ "$h" =~ ^[A-Za-z0-9.-]+$ ]]; then continue; fi
    valid=1
    IFS='.' read -ra labels <<< "$h"
    for lbl in "${labels[@]}"; do
      if [[ -z "$lbl" || ${#lbl} -gt 63 ]]; then valid=0; break; fi
      if ! [[ "$lbl" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then valid=0; break; fi
    done
    (( valid )) || continue
    [[ -n "$hostname6" ]] && hostname6+=" • "
    hostname6+="$h"
  done
fi

#
# Determine default outbound network interface and fetch local IPv4 address.
iface=$(route get default 2>/dev/null | awk '/interface:/ {print $2}')
local_ip4=$(ipconfig getifaddr "$iface" 2>/dev/null || echo "")
# Fetch local IPv6 address on the same interface (global-scope only).
local_ip6=$(ifconfig "$iface" 2>/dev/null \
  | awk '/inet6 / && !/fe80/ {print $2; exit}' \
  | sed 's/%.*//')
ip6="$local_ip6"

#
# Construct Unicode flag emoji from ISO country code.
flag=$(flag_from_iso "$country_iso")

#
# Choose network icon for the menu bar.
# If Tailscale exit node is in use, display a specific icon.
network_icon="􀤆"
if command -v tailscale &>/dev/null; then
  exit_node_in_use=$(echo "$TSCACHE_JSON" | jq -r '.ExitNodeStatus.Online // false')
  if [[ "$exit_node_in_use" == "true" ]]; then
    network_icon="􁅏"
  fi
fi

#
# Detect if a Mullvad exit node is in use.
mullvad_exit_node_used=""
mullvad_line=$(tailscale status | grep mullvad.ts.net | head -n1)
if [[ -n "$mullvad_line" ]]; then
  # Extract the node name (fqdn)
  mullvad_exit_node_used=$(echo "$mullvad_line" | awk '{print $2}')
fi

#
# Fetch ISP logo/icon from CDN, fallback to favicon if unavailable.
# Encode image in base64 for inline display in SwiftBar menu.
# --- ISP logo logic: prefer UI logo, fallback to favicon, else no logo ---
asn_fmt=$(echo "$asn" | tr '[:upper:]' '[:lower:]' | sed 's/as//g')
image_url="https://static.ui.com/asn/${asn_fmt}_101x101.png"
whois_domain="$(provider_domain_for "$asn" "$asn_org" "")"
favicon_url="https://t3.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${whois_domain}&size=128"

# TTL for logo/favicons
logo_ttl=$((24 * 3600))

image_enc=""

# 1) Try cached UI logo (download and cache if needed)
logo_path="$(cache_url image "$image_url" "$logo_ttl" "" 16 nofollow)"
if [[ -n "$logo_path" && -s "$logo_path" ]]; then
  image_enc=$(base64 < "$logo_path")
fi

# 2) Fallback to favicon service if no logo
if [[ -z "$image_enc" && -n "$whois_domain" ]]; then
  fav_path="$(cache_url image "$favicon_url" "$logo_ttl" "" 16)"
  if [[ -n "$fav_path" && -s "$fav_path" ]]; then
    image_enc=$(base64 < "$fav_path")
  fi
fi

#
# Output main menu bar icon, ISP/operator name, and ASN info.
# Add clickable links for ASN lookups, and display city, country (with flag), and time zone.
# Show logo as menu image if available.
# If a Mullvad exit node is active, display "Mullvad" instead of asn_org_f.

ip_icons=""

if [[ -n "$pub_ip6" ]]; then
  ip_icons+="􀃕"
else
  ip_icons+="􀃔"
fi
if [[ -n "$pub_ip4" ]]; then
  ip_icons+="􀃑"
else
  ip_icons+="􀃐"
fi

tailscale_bar_icon=""

if [[ "$ts_online" == "true" ]]; then
  tailscale_bar_icon="􀂻"
else
  tailscale_bar_icon="􀂺"
fi

#
# Map ASN organization to a short, standardized name for display.
asn_org_f="$(map_operator_name "$asn_org")"
asn_org_s="$asn_org_f"
# Truncate operator name if longer than 10 characters, remove trailing space if present
if [[ ${#asn_org_f} -gt 12 ]]; then
  truncated="$(echo "$asn_org_f" | cut -c1-12)"
  [[ "${truncated: -1}" == " " ]] && truncated="${truncated:0:11}"
  asn_org_f="${truncated}..."
fi

# if [[ "$exit_node_in_use" == "true" ]]; then
#   if [[ "$mullvad_exit_node_used" == *.mullvad.ts.net ]]; then
#     asn_org_f="Mullvad"
#   fi
# fi

exitnode_icon="􀄌" # Default: no exit node
if [[ "$exit_node_in_use" == "true" ]]; then
  exitnode_icon="􀄍"
fi
echo "${network_icon}  ${asn_org_f} ${ip_icons}${tailscale_bar_icon}${exitnode_icon}"

echo "---"
# Only display image if set and valid (avoid empty lines when logo is missing).
# if [[ -n "$image_enc" && "${#image_enc}" -gt 100 ]]; then
#   echo " | image=${image_enc}"
# fi

echo "Fournisseur Internet"

# Show ASN operator name and clickable AS numbers.
# Handle case where IPv4 and IPv6 ASN differ.
asn4=$(jq -r '.asn // empty' <<<"$json4")
asn6=$(jq -r '.asn // empty' <<<"$json6")
asn=""
isp_line=""
if [[ -n "$asn4" && -n "$asn6" ]]; then
  if [[ "$asn4" == "$asn6" ]]; then
    asn="$asn4"
    isp_line+="${asn_org_s} • $asn4"
  else
    asn="$asn6"
    isp_line+="${asn_org_s} • $asn6 • $asn4"
  fi
elif [[ -n "$asn4" ]]; then
  asn="$asn4"
  isp_line+="${asn_org_s} • $asn4"
elif [[ -n "$asn6" ]]; then
  asn="$asn6"
  isp_line+="${asn_org_s} • $asn6"
fi
# if [[ -n "$whois_domain" ]]; then
#   echo "→ ${whois_domain} 􀁜 | size=10 href=http://${whois_domain}"
# fi

isp_localization_line=""
[[ -n "$city"   ]] && isp_localization_line+="${city}, "
if [[ -n "$country" ]]; then
  if [[ "$country_eu" == "true" ]]; then
    isp_localization_line+="${country} ${flag} 🇪🇺"
  else
    isp_localization_line+="${country} ${flag}"
  fi
fi

echo "${isp_line} • ${isp_localization_line} | href=https://radar.cloudflare.com/${asn} image=${image_enc}"

# If city or country is available, provide menu entry to open location in Apple Maps.
# if [[ -n "$city" || -n "$country" ]]; then
#   query=$(printf '%s %s' "$city" "$country" \
#     | tr '[:upper:]' '[:lower:]' \
#     | sed 's/ /%20/g')
#   echo "${isp_localization_line} | href=maps://?q=${query}"
#   # echo "${menu_open_in_maps} | size=10 href=maps://?q=${query}"
# fi
# [[ -n "$tz"     ]] && echo "$tz 􀐫 | size=10"

#
# Fetch DNS servers used by default interface, separate IPv4 and IPv6.
# Remove interface scope from DNS entries.
# If none found for interface, fall back to all system DNS servers.
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
# Remove trailing delimiter.
dns4=${dns4%% • }
dns6=${dns6%% • }

# Fallback: if no DNS found for interface, show all system DNS servers.
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

# Get default IPv4 and IPv6 gateways, remove interface scope from IPv6.
gw4=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
gw6=$(route -n get -inet6 default 2>/dev/null | awk '/gateway:/ {print $2}')
# Remove any scope suffix from IPv6 gateway
gw6=${gw6%%\%*}

echo "---"

network_lines=()

#
# Fetch DNS resolver information and format label for display.
# Try NextDNS detection first. Measure DNS latency using ICMP ping or DNS query time.
resolver_name=""
resolver_label=""
nextdns_test_json="$NEXTDNS_TEST_JSON"
nextdns_status=$(echo "$nextdns_test_json" | jq -r '.status // empty')
if [[ "$nextdns_status" == "ok" ]]; then
  resolver_name="NextDNS"
  # Harmonize: apply mapping to resolver_name
  resolver_name="$(map_operator_name "$resolver_name")"
  resolver_proto=$(echo "$nextdns_test_json" | jq -r '.protocol // empty')
  resolver_server=$(echo "$nextdns_test_json" | jq -r '.server // empty')
  # Extract location code from server (e.g. netbarista-par-1 → PAR)
  if [[ "$resolver_server" =~ -([a-z]{3})-([0-9]+)$ ]]; then
    cf_colo="${BASH_REMATCH[1]}"
    cf_colo_upper=$(echo "$cf_colo" | tr '[:lower:]' '[:upper:]')
    cf_iso=$(cf_colo_to_iso "$cf_colo_upper")
    resolver_flag=$(flag_from_iso "$cf_iso")
    resolver_display="$resolver_name"
    # Append ASN after provider name if available (done below after ASN is fetched)
    resolver_display+=" • $resolver_proto • $resolver_server"
    if [[ -n "$resolver_flag" ]]; then
      resolver_display+=" $resolver_flag"
    fi
  else
    resolver_display="$resolver_name"
    # Append ASN after provider name if available (done below after ASN is fetched)
    resolver_display+=" • $resolver_proto • $resolver_server"
  fi
  # Measure DNS latency for the resolver: try ICMP ping, fallback to DNS query latency via system resolver.
  resolver_ip="$resolver_server"
  if [[ "$resolver_name" == "NextDNS" ]]; then
    resolver_ip=$(echo "$nextdns_test_json" | jq -r '.destIP // empty')
  fi

  # --- DNS provider logo (UI ASN, fallback to favicon) ---
  dns_image_enc=""
  dns_asn=""; dns_asn_org=""; dns_whois_domain=""; dns_logo_path=""; dns_fav_path=""
  if [[ -n "$resolver_ip" ]]; then
    dns_info_json=$(cache_url json "https://ip.rslt.fr/json?ip=$resolver_ip" "$IP_JSON_TTL")
    dns_asn=$(echo "$dns_info_json" | jq -r '.asn // empty')
    dns_asn_org=$(echo "$dns_info_json" | jq -r '.asn_org // empty')
    dns_country_eu=$(echo "$dns_info_json" | jq -r '.country_eu // empty')
    # Append ASN after DNS provider name (right after provider name, before other info)
    if [[ -n "$dns_asn" ]]; then
      resolver_display="${resolver_display/NextDNS/NextDNS (AS$dns_asn)}"
    fi
  fi
  # Append EU flag if resolver is in the EU (based on ip.rslt.fr JSON), similar to ISP logic
  if [[ "$dns_country_eu" == "true" && "$resolver_display" != *"🇪🇺"* ]]; then
    resolver_display+=" 🇪🇺"
  fi
  if [[ -n "$dns_asn" ]]; then
    dns_asn_fmt=$(echo "$dns_asn" | tr '[:upper:]' '[:lower:]' | sed 's/as//g')
    dns_image_url="https://static.ui.com/asn/${dns_asn_fmt}_101x101.png"
    dns_logo_path="$(cache_url image "$dns_image_url" "$logo_ttl" "" 16 nofollow)"
    if [[ -n "$dns_logo_path" && -s "$dns_logo_path" ]]; then
      dns_image_enc=$(base64 < "$dns_logo_path")
    fi
    if [[ -z "$dns_image_enc" ]]; then
      dns_whois_domain="$(provider_domain_for "$dns_asn" "$dns_asn_org" "$resolver_ip")"
      if [[ -n "$dns_whois_domain" ]]; then
        dns_favicon_url="https://t3.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${dns_whois_domain}&size=128"
        dns_fav_path="$(cache_url image "$dns_favicon_url" "$logo_ttl" "" 16)"
        if [[ -n "$dns_fav_path" && -s "$dns_fav_path" ]]; then
          dns_image_enc=$(base64 < "$dns_fav_path")
        fi
      fi
    fi
  fi

  dns_latency=""
  if ping -c 2 -W 1 "$resolver_ip" &>/dev/null; then
    dns_latency=$(ping -c 2 -q "$resolver_ip" | awk -F'/' '/^rtt/ {print int($5)}')
  fi
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
  # --- PTR lookup for resolver_ip ---
  resolver_ptr=""
  if [[ -n "$resolver_ip" ]] && { is_ipv4 "$resolver_ip" || is_ipv6 "$resolver_ip"; }; then
    resolver_ptr=$(dig -x "$resolver_ip" +short | awk 'NF' \
      | sed 's/\.$//' \
      | awk '!/\\/' \
      | awk '/^[A-Za-z0-9.-]+$/' \
      | head -n1)
  fi
  # Append PTR if not empty and not already present
  if [[ -n "$resolver_ptr" && "$resolver_display" != *"$resolver_ptr"* ]]; then
    resolver_display+=" • $resolver_ptr"
  fi
  case "$lang" in
    fr)
      if [[ -n "$dns_image_enc" ]]; then
        resolver_label="$resolver_display | image=${dns_image_enc} refresh=true"
      else
        resolver_label="$resolver_display | refresh=true"
      fi
      ;;
    *)
      if [[ -n "$dns_image_enc" ]]; then
        resolver_label="DNS: $resolver_display | image=${dns_image_enc} refresh=true"
      else
        resolver_label="DNS: $resolver_display | refresh=true"
      fi
      ;;
  esac
  if [[ -n "$dns_latency_avg" ]]; then
    resolver_display+=" • $dns_latency_avg"
    resolver_label="${resolver_label%| refresh=true} • $dns_latency_avg | refresh=true"
    resolver_label="${resolver_label%| image=* refresh=true} • $dns_latency_avg | image=${dns_image_enc} refresh=true"
  fi
else
  resolver_ip=$(curl -sL https://test.nextdns.io/ | jq -r '.resolver // empty')
  if [[ -n "$resolver_ip" ]]; then
    dns_info_json=$(cache_url json "https://ip.rslt.fr/json?ip=$resolver_ip" "$IP_JSON_TTL")
    resolver_name=$(echo "$dns_info_json" | jq -r '.asn_org // empty')
    resolver_name="$(map_operator_name "$resolver_name")"
    dns_asn=$(echo "$dns_info_json" | jq -r '.asn // empty')
  fi
  dns_latency=""
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
    fi
  fi
  dns_latency_avg=""
  if [[ -n "$dns_latency" ]]; then
    dns_latency_avg="${dns_latency} ms"
  fi

  if [[ -n "$resolver_name" && "$resolver_name" != "null" ]]; then
    resolver_flag=""
    resolver_info="$resolver_name"
    # Append ASN after DNS provider name (right after provider name, before other info)
    if [[ -n "$dns_asn" ]]; then
      resolver_info+=" • $dns_asn"
    fi
    # For other resolvers: fetch city and country via ip.rslt.fr/json and build flag.
    dns_info_json=$(cache_url json "https://ip.rslt.fr/json?ip=$resolver_ip" "$IP_JSON_TTL")
    dns_country_iso=$(echo "$dns_info_json" | jq -r '.country_iso // empty')
    dns_country=$(echo "$dns_info_json" | jq -r '.country // empty')
    dns_city=$(echo "$dns_info_json" | jq -r '.city // empty')
    dns_country_eu=$(echo "$dns_info_json" | jq -r '.country_eu // empty')

    # --- DNS provider logo (UI ASN, fallback to favicon) ---
    dns_image_enc=""
    # dns_asn already set above
    if [[ -n "$dns_asn" ]]; then
      dns_asn_fmt=$(echo "$dns_asn" | tr '[:upper:]' '[:lower:]' | sed 's/as//g')
      dns_image_url="https://static.ui.com/asn/${dns_asn_fmt}_101x101.png"
      dns_logo_path="$(cache_url image "$dns_image_url" "$logo_ttl" "" 16 nofollow)"
      if [[ -n "$dns_logo_path" && -s "$dns_logo_path" ]]; then
        dns_image_enc=$(base64 < "$dns_logo_path")
      fi
      if [[ -z "$dns_image_enc" ]]; then
        dns_whois_domain="$(provider_domain_for "$dns_asn" "$(echo "$dns_info_json" | jq -r '.asn_org // empty')" "$resolver_ip")"
        if [[ -n "$dns_whois_domain" ]]; then
          dns_favicon_url="https://t3.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${dns_whois_domain}&size=128"
          dns_fav_path="$(cache_url image "$dns_favicon_url" "$logo_ttl" "" 16)"
          if [[ -n "$dns_fav_path" && -s "$dns_fav_path" ]]; then
            dns_image_enc=$(base64 < "$dns_fav_path")
          fi
        fi
      fi
    fi

    resolver_flag=$(flag_from_iso "$dns_country_iso")

    resolver_location=""

    if [[ -n "$dns_city" ]]; then
      resolver_location+="${dns_city}, "
    fi

    if [[ -n "$dns_country" ]]; then
      resolver_location+="${dns_country}"
    fi

    resolver_info+=" • ${resolver_location}"

    if [[ -n "$resolver_flag" ]]; then
      resolver_info="${resolver_info} $resolver_flag"
    fi
    # Append EU flag if resolver is in the EU (based on ip.rslt.fr JSON), similar to ISP logic
    if [[ "$dns_country_eu" == "true" ]]; then
      resolver_info+=" 🇪🇺"
    fi

    if [[ "$resolver_name" == "Cloudflare" ]]; then
      cf_trace=$(curl -sL --max-time 2 https://one.one.one.one/cdn-cgi/trace)
      cf_colo=$(echo "$cf_trace" | grep '^colo=' | awk -F= '{print $2}')
      if [[ -n "$cf_colo" ]]; then
        resolver_info+=" • ${cf_colo}"
      fi
    fi
    # --- PTR lookup for resolver_ip ---
    resolver_ptr=""
    if [[ -n "$resolver_ip" ]] && { is_ipv4 "$resolver_ip" || is_ipv6 "$resolver_ip"; }; then
      resolver_ptr=$(dig -x "$resolver_ip" +short | awk 'NF' \
        | sed 's/\.$//' \
        | awk '!/\\/' \
        | awk '/^[A-Za-z0-9.-]+$/' \
        | head -n1)
    fi
    if [[ -n "$resolver_ptr" && "$resolver_info" != *"$resolver_ptr"* ]]; then
      resolver_info+=" • $resolver_ptr"
    fi
  fi

  if [[ -n "$dns_latency_avg" ]]; then
    resolver_info+=" • $dns_latency_avg"
  fi

  case "$lang" in
    fr)
      if [[ -n "$dns_image_enc" ]]; then
        resolver_label="$resolver_info | image=${dns_image_enc} refresh=true"
      else
        resolver_label="$resolver_info | refresh=true"
      fi
      ;;
    *)
      if [[ -n "$dns_image_enc" ]]; then
        resolver_label="$resolver_info | image=${dns_image_enc} refresh=true"
      else
        resolver_label="$resolver_info | refresh=true"
      fi
      ;;
  esac
fi

if [[ -n "$resolver_label" ]]; then
  # Append latency once if not already present
  if [[ -n "$dns_latency_avg" && "$resolver_label" != *"$dns_latency_avg"* ]]; then
    resolver_label="${resolver_label%| refresh=true} • $dns_latency_avg | refresh=true"
  fi
  # Insert a separator under local DNS info (host name, search domains) before the public resolver line
  if [[ ${#network_lines[@]} -gt 0 ]]; then
    network_lines+=("---")
  fi
  network_lines+=("$resolver_label")
fi

#
# Build section with general network information: host name, search domains, DNS resolver info.

network_lines+=("---")
network_lines+=("${menu_network}")

[[ -n "$(hostname)" ]] && network_lines+=("${menu_host_name} : $(hostname) | refresh=true")
# Get search domains in use and display as a single line.
search_domains=$(scutil --dns | awk -F': ' '/search domain\[[0-9]+\]/ {print $2}' | sort -u)
sd=$(echo "$search_domains" | tr '\n' ',' | sed 's/,$//; s/,/ • /g')
if [[ -n "$sd" ]]; then
  network_lines+=("${menu_search_domains} : $sd | refresh=true")
fi

if [[ ${#network_lines[@]} -gt 0 ]]; then
  echo "${menu_dns_provider}"
  printf "%s\n" "${network_lines[@]}"
  echo "---"
fi

#
# IPv6 section: display relevant IPv6 addresses, DNS servers, gateways, hostnames, and global IPv6 addresses per interface.
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

#
# IPv4 section: display public and local IPv4 addresses, DNS servers, gateways, hostnames, and IPv4 addresses per interface.
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

#
# Wi-Fi section: display current SSID, Wi-Fi version, frequency, channel, bandwidth, signal, transmit rate, and security.
# Only shown if Wi-Fi interface is active and connected.
ssid=$(echo "$SPCACHE" | awk '/Current Network Information:/ {getline; gsub(/^ +|:$/,""); print; exit}')
if [[ -n "$ssid" ]]; then
  sp_info=$(echo "$SPCACHE" | awk '/Other Local Wi-Fi Networks:/ {exit} {print}')
  # Extract Country Code from main block (not Current Network Information), to display the regulatory domain flag.
  wifi_country_code=$(echo "$sp_info" | awk -F'Country Code: ' '/Country Code: / {print $2; exit}')
  # Generate flag from country code
  wifi_country_flag=$(flag_from_iso "$wifi_country_code")
  phy=$(echo "$sp_info" | awk -F': ' '/PHY Mode:/{print $2; exit}')
  # Map 802.11 PHY modes to Wi-Fi generation labels (including Wi-Fi 8 / 802.11bn).
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
  # Extract channel, bandwidth, frequency, signal, transmit rate, security from system_profiler output.
  wifi_channel_line=$(echo "$sp_info" | awk -F'Channel: ' '/Channel: / {print $2; exit}')
  wifi_channel_num=$(echo "$wifi_channel_line" | awk '{print $1}')
  wifi_bandwidth=$(echo "$wifi_channel_line" | grep -o '[0-9]\+MHz')
  wifi_channel=$(echo "$wifi_channel_line" | awk '{print $1}')
  # Frequency label: determine frequency band label (2.4 GHz, 5 GHz, 6 GHz) from channel number.
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
  # Signal (dBm), Noise (dBm), and transmit rate: all extracted from system_profiler output.
  wifi_signal_noise_line=$(echo "$sp_info" | awk -F'Signal / Noise: ' '/Signal \/ Noise:/ {print $2; exit}')
  wifi_signal=$(echo "$wifi_signal_noise_line" | awk '{print $1}')
  wifi_noise=$(echo "$wifi_signal_noise_line" | awk -F'/' '{if (NF > 1) print $2}' | awk '{print $1}')
  wifi_txrate_sp=$(echo "$sp_info" | awk -F'Transmit Rate: ' '/Transmit Rate:/ {print $2; exit}' | grep -Eo '[0-9]+')
  # Security
  wifi_security=$(echo "$sp_info" | awk '/Current Network Information:/,0' | awk -F'Security: ' '/Security: / {print $2; exit}')

  echo "---"

  # Calculate SNR (Signal-to-Noise Ratio) and Wi-Fi quality icon for quick visual feedback.
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

  # First line: SSID • Wi-Fi X (802.11xx) • Frequency (if present).
  wifi_line="${wifi_quality_stars} ${ssid} • $wifi_ver ($phy)"
  if [[ -n "$wifi_freq_label_sp" ]]; then
    wifi_line+=" • $wifi_freq_label_sp"
  fi
  echo "${wifi_line} | refresh=true"
  # Sub-lines: Channel, Bandwidth, Signal, Transmit rate, Security.
  # Channel and Bandwidth are shown together for compactness.
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
  # Signal: show signal strength in dBm.
  case "$lang" in
    fr) sig_label="Signal" ; noise_label="Bruit" ;;
    *)  sig_label="Signal" ; noise_label="Noise" ;;
  esac
  if [[ -n "$wifi_signal" ]]; then
    printf "%s : %s dBm | refresh=true\n" "$sig_label" "$wifi_signal"
  fi
  # Noise: show noise floor in dBm.
  if [[ -n "$wifi_noise" ]]; then
    printf "%s : %s dBm | refresh=true\n" "$noise_label" "$wifi_noise"
  fi
  # Transmit rate (convert to Gbps if >=1000 Mbps, locale-aware).
  case "$lang" in
    fr) rate_label="Débit" ;;
    *)  rate_label="Transmit rate" ;;
  esac
  # Only show transmit rate if strictly greater than zero to avoid displaying inactive values.
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
  # Security: show the Wi-Fi security protocol in use (WPA2, WPA3, etc).
  case "$lang" in
    fr) sec_label="Sécurité" ;;
    *)  sec_label="Security" ;;
  esac
  if [[ -n "$wifi_security" ]]; then
    printf "%s : %s | refresh=true\n" "$sec_label" "$wifi_security"
  fi
fi

#
# If Tailscale is online, display Tailscale information: DERP relay, machine tags, and all peers.
# For each peer, display connection status, OS, tags, last seen, relay location, and routes.
if [[ "$ts_online" == "true" ]]; then
  # Nearest DERP and its latency: show the nearest relay node and its measured latency.
  nearest_derp=""
  derp_latency=""
  if command -v tailscale &>/dev/null; then
    nearest_derp=$(echo "$TSCACHE_NETCHECK" | awk -F': ' '/Nearest DERP:/ {print $2}' | xargs)
    if [[ -n "$nearest_derp" ]]; then
      derp_latency=$(echo "$TSCACHE_NETCHECK" \
        | awk -v city="$nearest_derp" '$0 ~ "- " && $0 ~ city {print}' \
        | sed -nE 's/.*: *([0-9.]+)ms.*/\1/p' \
        | head -n1)
    fi
  fi

  ts_lines=()
  # Machine tags: display tags associated with the local Tailscale node.
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

  # Extract the Tailscale IP of the active exit node (if any), for display and status indication.
  if [[ -n "$exit_node_id" && -n "$ts_json" ]]; then
    active_exit_ip=$(echo "$ts_json" | jq -r --arg id "$exit_node_id" '.Peer[] | select(.ID == $id) | .TailscaleIPs[]? | select(test(":") | not)')
  fi

    if [[ -n "$magicdns_org" || -n "$magicdns_domain" ]]; then
      org_domain_str=""
      [[ -n "$magicdns_org" ]] && org_domain_str="$magicdns_org"
      if [[ -n "$magicdns_domain" ]]; then
        [[ -n "$org_domain_str" ]] && org_domain_str+=" • "
        org_domain_str+="$magicdns_domain"
      fi
      ts_lines+=("$org_domain_str | refresh=true")
      # Add Tailscale IPv6 then IPv4 immediately below
      if [[ -n "$ts_ip6" ]]; then
        ts_lines+=("${menu_ipv6} : $ts_ip6 | refresh=true")
      fi
      if [[ -n "$ts_ip4" ]]; then
        ts_lines+=("${menu_ipv4} : $ts_ip4 | refresh=true")
      fi
    fi
  #
  # Map DERP relay code to ISO country code for flag display.
  derp_to_iso() {
    case "$1" in
      PAR) echo "FR";;
      AMS) echo "NL";;
      FRA|NUE) echo "DE";;
      LHR) echo "GB";;
      NRT) echo "JP";;
      SIN) echo "SG";;
      SYD) echo "AU";;
      HKG) echo "HK";;
      IAD|SEA|SFO|SJC|CHI) echo "US";;
      YVR|YYZ) echo "CA";;
      BRL) echo "BR";;
      DUB) echo "IE";;
      WAW) echo "PL";;
      *) echo "$1";;
    esac
  }

  #
  # If a DERP relay is used, display its code, country flag, city, and latency if available.
  # This provides additional transparency about relay usage and location.
  self_relay=$(echo "$ts_json" | jq -r '.Self.Relay // empty')
  if [[ -n "$self_relay" ]]; then
    rc_upper=$(echo "$self_relay" | tr '[:lower:]' '[:upper:]')
    iso=$(derp_to_iso "$rc_upper")
    relay_flag=$(flag_from_iso "$iso")
    # Parse DERP city and latency for display with DERP info
    derp_city=""
    derp_latency=""
    if [[ -n "$rc_upper" ]]; then
      lower_rc_upper=$(echo "$rc_upper" | tr '[:upper:]' '[:lower:]')
      derp_line=$(echo "$TSCACHE_NETCHECK" | awk -v code="$lower_rc_upper" '
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
  # Each peer is displayed with its status, IP addresses, OS, tags, last seen time, and relay location.
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
      # Status text: parse peer status for direct/relay/exit node/online/offline.
      status_txt=$(echo "$ts_line" | awk '{for(i=5;i<=NF;++i) printf $i" "; print ""}' | sed 's/[ ,]*$//')
      icon=""
      exiticon=""
      offlineicon=""
      relayicon=""
      opts=""
      if [[ "$status_txt" == *direct* ]]; then icon="   􀄭 "; fi
      if [[ "$status_txt" == *"offers exit node"* ]]; then exiticon="􁏝 "; fi
      if [[ "$status_txt" == *"exit node"* && "$ip" == "$active_exit_ip" ]]; then exiticon="􀐳 "; fi
      if [[ "$status_txt" == *offline* ]]; then offlineicon="􁣡 "; fi
      if [[ "$status_txt" == *'relay "'* ]]; then relayicon="   􀅌 "; fi
      if [[ "$status_txt" != "-" && "$status_txt" != *offline* && "$status_txt" != *idle* ]]; then opts=" | refresh=true"; fi

      # Extract direct/relay info from status_txt for display (for advanced users).
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
      # Peer line (name/IP + icons): format peer display line with icons and status.
      if [[ "$is_self" == "1" ]]; then
        peer_display_name="--􀉩 ${offlineicon}${exiticon}${name}${icon}${relayicon}${direct_info}$opts | href=https://login.tailscale.com/admin/machines/$ip"
      else
        peer_display_name="--${offlineicon}${exiticon}${name}${icon}${relayicon}${direct_info}$opts | href=https://login.tailscale.com/admin/machines/$ip"
      fi
      peer_lines=("$peer_display_name")

      # Add IPv4 address as subline.
      peer_lines+=("----${ip} | refresh=true")
      # Extract IPv6 Tailscale address for this peer (if any).
      if [[ "$is_self" == "1" ]]; then
        peer_ipv6=$(echo "$ts_json" | jq -r '.Self.TailscaleIPs[]? | select(test(":"))' | head -n1)
      else
        peer_ipv6=$(echo "$peer_json" | jq -r '.TailscaleIPs[]? | select(test(":"))' | head -n1)
      fi
      peer_ipv6=${peer_ipv6%%\%*}
      if [[ -n "$peer_ipv6" ]]; then
        peer_lines+=("----$peer_ipv6 | refresh=true")
      fi
      # Only print the FQDN (DNSName) ONCE, after all IPs, but only if MagicDNS is enabled.
      if [[ "$magicdns_enabled" == "true" ]]; then
        if [[ "$is_self" == "1" ]]; then
          fqdn=$(echo "$ts_json" | jq -r '.Self.DNSName // empty')
        else
          fqdn=$(echo "$peer_json" | jq -r '.DNSName // empty')
        fi
        if [[ -n "$fqdn" && "$fqdn" != "null" ]]; then
          fqdn_stripped=${fqdn%.}
          peer_lines+=("----$fqdn_stripped | refresh=true")
        fi
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
      # Set the OS icon based on OS type and device name.
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
        iso=$(derp_to_iso "$rc_upper")
        relay_flag=$(flag_from_iso "$iso")
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

  # --------- PATCH: Exit nodes list (private + Mullvad) ---------
  # This function builds a submenu of available Tailscale exit nodes, grouped by private and Mullvad nodes,
  # and further grouped by country for Mullvad nodes. This enables quick switching between exit nodes.
  print_tailscale_exitnodes() {
    case "$lang" in
      fr)
        exitnodes_label="Exit nodes"
        exitnodes_priv_label="Serveurs privés"
        exitnodes_mullvad_label="Serveurs Mullvad"
        disconnect_label="→ Déconnecter"
        ;;
      *)
        exitnodes_label="Exit nodes"
        exitnodes_priv_label="Private servers"
        exitnodes_mullvad_label="Mullvad servers"
        disconnect_label="→ Disconnect"
        ;;
    esac
    exitnodes_lines=()
    exitnodes_raw=$(tailscale exit-node list 2>/dev/null | tail -n +2)
    if [[ -n "$exitnodes_raw" ]]; then
      # Escape only the spaces in script_dir for use in bash=...
      escaped_script_dir="${script_dir// /\\ }"
      exitnodes_prive=()
      mullvad_raw_lines=()
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*IP[[:space:]] ]] && continue
        [[ -z "$line" ]] && continue

        line_pipe=$(echo "$line" | sed -E 's/  +/|/g')
        IFS='|' read -r ip host country city status <<<"$line_pipe"
        [[ -z "$host" || "$host" == "HOSTNAME" || "$host" == "To" ]] && continue

          if [[ "$host" =~ \.mullvad\.ts\.net$ ]]; then
            mullvad_raw_lines+=("$host|$country|$city|$status")
          else
            # Priority: selected → 􀒗, then status != - → 􀇾, else 􀨳
            if [[ "$status" == "selected" ]]; then
              icon="􀒗"
            elif [[ "$status" != "-" ]]; then
              icon="􀇾"
            else
              icon="􀨳"
            fi
            prefix=$(echo "$host" | awk -F'.' '{print $1}')
            exitnodes_prive+=("--$icon $prefix | bash=\"/Applications/Tailscale.app/Contents/MacOS/Tailscale\" param1=\"set\" param2=\"--exit-node\" param3=\"$prefix\" terminal=false refresh=true")
          fi
      done <<<"$exitnodes_raw"
      exitnodes_lines+=("→ $exitnodes_label")
      if [[ -n "$exit_node_used" ]]; then
        exitnodes_lines+=("--Actuel : $exit_node_used")
      fi
      if [[ "$exit_node_in_use" == "true" ]]; then
        exitnodes_lines+=("--$disconnect_label | bash=\"/Applications/Tailscale.app/Contents/MacOS/Tailscale\" param1=\"set\" param2=\"--exit-node=\" terminal=false refresh=true")
        exitnodes_lines+=("-----")
      fi
      if [[ ${#exitnodes_prive[@]} -gt 0 ]]; then
        exitnodes_lines+=("--$exitnodes_priv_label")
        exitnodes_lines+=("${exitnodes_prive[@]}")
      fi
      if [[ ${#exitnodes_prive[@]} -gt 0 && ${#mullvad_raw_lines[@]} -gt 0 ]]; then
        exitnodes_lines+=("-----")
      fi
      if [[ ${#mullvad_raw_lines[@]} -gt 0 ]]; then
        exitnodes_lines+=("--$exitnodes_mullvad_label")
        # --- Optimization: pre-group Mullvad nodes by country for easier navigation in the menu ---
        countries_list=()
        country_nodes=()
        idx=0
        for info in "${mullvad_raw_lines[@]}"; do
          _host=$(echo "$info" | cut -d'|' -f1)
          _country=$(echo "$info" | cut -d'|' -f2)
          _city=$(echo "$info" | cut -d'|' -f3)
          _status=$(echo "$info" | cut -d'|' -f4)
          [[ "$_country" == "-" ]] && continue

          # Find the country index or create it if not present
          found_idx=""
          for i in "${!countries_list[@]}"; do
            if [[ "${countries_list[$i]}" == "$_country" ]]; then found_idx=$i; break; fi
          done
          if [[ -z "$found_idx" ]]; then
            countries_list+=("$_country")
            country_nodes[$idx]=""
            found_idx=$idx
            ((idx++))
          fi

          node_name=$(echo "$_host" | awk -F'.' '{print $1}')
          # Priority: selected → 􀒗, then status != - → 􀇾, else 􀨳
          if [[ "$_status" == "selected" ]]; then
            icon="􀒗"
          elif [[ "$_status" != "-" ]]; then
            icon="􀇾"
          else
            icon="􀨳"
          fi
          city_display="$_city"
          [[ "$city_display" == "-" ]] && city_display=""
          if [[ "$city_display" == "Any" ]]; then
            if [[ "$lang" == "fr" ]]; then
              auto_label="→ Automatique"
            else
              auto_label="→ Automatic"
            fi
            node_line="----$auto_label | bash=\"/Applications/Tailscale.app/Contents/MacOS/Tailscale\" param1=\"set\" param2=\"--exit-node\" param3=\"$_host\" terminal=false refresh=true"
            # Prepend to keep "Any" first in the list
            country_nodes[$found_idx]="$node_line"${country_nodes[$found_idx]:+"${country_nodes[$found_idx]}"}
            # Mark a split to separate later when other cities exist
            country_nodes[$found_idx]+="__SPLIT__"
          else
            if [[ -n "$city_display" ]]; then
              node_line="----$icon $node_name • $city_display | bash=\"/Applications/Tailscale.app/Contents/MacOS/Tailscale\" param1=\"set\" param2=\"--exit-node\" param3=\"$_host\" terminal=false refresh=true"
            else
              node_line="----$icon $node_name | bash=\"/Applications/Tailscale.app/Contents/MacOS/Tailscale\" param1=\"set\" param2=\"--exit-node\" param3=\"$_host\" terminal=false refresh=true"
            fi
            country_nodes[$found_idx]+="$node_line"$'\n'
          fi
        done

        # Display each country only once, grouping nodes under it.
        for i in "${!countries_list[@]}"; do
          _country="${countries_list[$i]}"
          _nodes="${country_nodes[$i]}"
          # Look up the country code for the flag.
          country_code=""
          for info in "${mullvad_raw_lines[@]}"; do
            if [[ "$(echo "$info" | cut -d'|' -f2)" == "$_country" ]]; then
              country_code=$(echo "$info" | cut -d'|' -f1 | awk -F'-' '{print $1}' | tr '[:lower:]' '[:upper:]')
              break
            fi
          done
          flag=$(flag_from_iso "$country_code")
          exitnodes_lines+=("--$flag $_country")
          # Display: "Any/Automatic" node first, then separator, then other cities.
          if [[ "$_nodes" == *"__SPLIT__"* ]]; then
            before_sep="${_nodes%%__SPLIT__*}"
            after_sep="${_nodes#*__SPLIT__}"
            [ -n "$before_sep" ] && exitnodes_lines+=("$before_sep")
            [ -n "$after_sep" ] && exitnodes_lines+=("-------")
            # Clean up any leading empty line
            after_sep_clean=$(echo "$after_sep" | sed '/^$/d')
            [ -n "$after_sep_clean" ] && exitnodes_lines+=("$after_sep_clean")
          else
            [ -n "$_nodes" ] && exitnodes_lines+=("$_nodes")
          fi
        done
      fi
    fi
    if [[ ${#exitnodes_lines[@]} -gt 0 ]]; then
      ts_lines+=("${exitnodes_lines[@]}")
    fi
  }
  print_tailscale_exitnodes
  # --------- END PATCH Exit nodes ---------

  if [[ ${#ts_lines[@]} -gt 0 ]]; then
    echo "---"
    # Add Tailscale version to the menu label if available
    ts_version=$(tailscale version 2>/dev/null | head -n1 | xargs)
    menu_tailscale_version="$menu_tailscale"
    if [[ -n "$ts_version" ]]; then
      menu_tailscale_version="$menu_tailscale • $ts_version"
    fi
    echo "${menu_tailscale_version}"
    printf "%s\n" "${ts_lines[@]}"
  fi
fi

#
# Fetch and display DNS statistics and analytics using NextDNS API.
# Includes global stats, top contacted/blocked domains, GAFAM breakdown, and country breakdown.

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

# Calculate time periods for statistics: last hour, today, this month.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
this_hour=$(date -u +%Y-%m-%dT%H:00:00Z)
last_hour=$(date -u -v -1H +%Y-%m-%dT%H:00:00Z)
today=$(date -u +%Y-%m-%dT00:00:00Z)
month_start=$(date -u +%Y-%m-01T00:00:00Z)

periods_from=("$last_hour" "$today" "$month_start")
periods_to=("$now" "$now" "$now")

if [[ -n "$NEXTDNS_API_KEY" && -n "$NEXTDNS_PROFILE_ID" ]]; then
  echo "---"

# Test NextDNS connection and show server and protocol in use.
  nextdns_test_json=$(curl -L --max-time 2 https://test.nextdns.io/)
  test_status=$(jq -r '.status // empty' <<<"$nextdns_test_json")
  if [[ "$test_status" == "ok" ]]; then
    proto=$(jq -r '.protocol // empty' <<<"$nextdns_test_json")
    server=$(jq -r '.server // empty' <<<"$nextdns_test_json")
    echo "$nextdns_menu • ${NEXTDNS_PROFILE_ID} • $server • $proto"
  else
    echo "$nextdns_menu • ${NEXTDNS_PROFILE_ID} 􀇾"
  fi

# For each period, fetch and display total and blocked DNS queries.
  for i in "${!periods_from[@]}"; do
    label="${period_labels[$i]}"
    from="${periods_from[$i]}"
    to="${periods_to[$i]}"
    json=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" \
      "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/status?from=$from&to=$to")
    total=$(jq '[.data[] | select(.status=="default")][0].queries // 0' <<<"$json")
    blocked=$(jq '[.data[] | select(.status=="blocked")][0].queries // 0' <<<"$json")
    pct="0"
    if [[ "$total" != "0" && "$total" != "" ]]; then
      pct=$(awk "BEGIN {printf \"%.1f\", 100*$blocked/$total}")
    fi
    echo "$label $(format_number $total) ${queries_label} • $(format_number $blocked) ${blocked_label} • $pct% | refresh=true"
  done

# Add year-to-date statistics.
  case "$lang" in
    fr) year_label="􀀄" ;;
    *)  year_label="􀀴" ;;
  esac
  from=$(date -u -v-1y +%Y-%m-%dT%H:%M:%SZ)
  to="$now"
  json_year=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" \
    "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/status?from=$from&to=$to")
  total=$(jq '[.data[] | select(.status=="default")][0].queries // 0' <<<"$json_year")
  blocked=$(jq '[.data[] | select(.status=="blocked")][0].queries // 0' <<<"$json_year")
  pct="0"
  if [[ "$total" != "0" && "$total" != "" ]]; then
    pct=$(awk "BEGIN {printf \"%.1f\", 100*$blocked/$total}")
  fi
  echo "$year_label $(format_number $total) ${queries_label} • $(format_number $blocked) ${blocked_label} • $pct% | refresh=true"

# Display all-time NextDNS statistics.
  json_alltime=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" \
    "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/status")
  total=$(jq '[.data[] | select(.status=="default")][0].queries // 0' <<<"$json_alltime")
  blocked=$(jq '[.data[] | select(.status=="blocked")][0].queries // 0' <<<"$json_alltime")
  pct="0"
  if [[ "$total" != "0" && "$total" != "" ]]; then
    pct=$(awk "BEGIN {printf \"%.1f\", 100*$blocked/$total}")
  fi
  echo "􀵏 $(format_number $total) ${queries_label} • $(format_number $blocked) ${blocked_label} • $pct% | refresh=true"

# Show top 20 contacted and blocked domains as submenus.
  if [[ "$lang" == "fr" ]]; then
    domains_label="→ Domaines les plus contactés"
    blocked_domains_label="→ Domaines les plus bloqués"
  else
    domains_label="→ Most contacted domains"
    blocked_domains_label="→ Most blocked domains"
  fi

# Function to fetch and print a domain list (contacted or blocked), limit to 20 domains.
  print_domains() {
    url="$1"
    submenulabel="$2"
    cursor=""
    count=0
    echo "$submenulabel"
    while true; do
      fullurl="$url"
      [[ -n "$cursor" ]] && fullurl="${url}&cursor=${cursor}"
    domains_json=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" "$fullurl")
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

# GAFAM requests breakdown submenu: show percentage of queries to major tech companies.
  gafam_json=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/destinations?type=gafam")
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

# Countries breakdown submenu: show percentage of queries by country, with flag and top domains.
  all_countries_json=""
  cursor=""
  while true; do
    fullurl="https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/destinations?type=countries"
    [[ -n "$cursor" ]] && fullurl="${fullurl}&cursor=${cursor}"
    page_json=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" "$fullurl")
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
        flag=$(flag_from_iso "$code")
        rounded_pct=$(awk "BEGIN {printf \"%.1f\", $pct}")
        if [[ -n "$name" && -n "$code" ]]; then
          if [[ $(awk "BEGIN {print ($rounded_pct >= 0.1)}") -eq 1 ]]; then
            echo "--$flag $name • $rounded_pct% | refresh=true"
          else
            echo "--$flag $name • < 0.1% | refresh=true"
          fi
        fi
        # Show top domains for this country as submenu for further drill-down.
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

# NextDNS Query Types breakdown (top 10 query types by percentage).
  querytypes_json=$(curl -L --max-time 3 -s -H "X-Api-Key: $NEXTDNS_API_KEY" "https://api.nextdns.io/profiles/$NEXTDNS_PROFILE_ID/analytics/queryTypes")
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
