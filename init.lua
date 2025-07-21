-- Hammerspoon: Reload SwiftBar plugins on network changes
--------------------------------------------------------------------------------
-- 1. Variables and functions
--------------------------------------------------------------------------------

-- Keep in memory the last known SSID
local lastSSID = hs.wifi.currentNetwork()

-- SwiftBar refresh function
local function refreshSwiftBar()
    local now = os.date("%Y-%m-%d %H:%M:%S")
    print("🔄 SwiftBar refresh triggered at", now)
    hs.execute("open -g 'swiftbar://refreshallplugins'")
end

--------------------------------------------------------------------------------
-- 2. Callbacks
--------------------------------------------------------------------------------

-- Callback for Internet connectivity changes
local function networkChangedCallback(self, flags)
    local status = hs.network.reachability.flags
    local reachable = (flags & status.reachable) ~= 0
    print(("🌐 Network reachability changed - reachable: %s"):format(tostring(reachable)))
    refreshSwiftBar()
end

-- Callback for Wi‑Fi SSID changes
local function wifiChangedCallback(watcher, eventType, interfaceName)
    local newSSID = hs.wifi.currentNetwork()
    print("📶 Wi‑Fi change detected:", eventType, interfaceName, "→ new SSID:", newSSID)

    if newSSID and newSSID ~= lastSSID then
        refreshSwiftBar()
    else
        print("🔁 No valid SSID change — nil or unchanged (lastSSID:", lastSSID, ")")
    end

    lastSSID = newSSID
end

--------------------------------------------------------------------------------
-- 3. Watchers configuration
--------------------------------------------------------------------------------

-- Internet reachability watcher
networkWatcher = hs.network.reachability.internet()
networkWatcher:setCallback(networkChangedCallback)
networkWatcher:start()
print("✅ Network reachability watcher started.")

-- Wi‑Fi SSID watcher
wifiWatcher = hs.wifi.watcher.new(wifiChangedCallback)
wifiWatcher:start()
print("✅ Wi‑Fi SSID watcher started.")

--------------------------------------------------------------------------------
-- 4. Startup info
--------------------------------------------------------------------------------

print("📡 SwiftBar auto-refresh on real SSID changes enabled.")
