package com.loki.trafficlab;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.RouteInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.ScanResult;
import android.os.BatteryManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.SystemClock;
import android.os.PowerManager;
import android.provider.Settings;
import android.telephony.CellInfo;
import android.telephony.CellSignalStrength;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.MessageDigest;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class AndroidNetworkDiagnostics {
    private AndroidNetworkDiagnostics() {}

    static boolean hasActiveVpn(Context context) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        if (manager == null) return false;
        try {
            for (Network network : manager.getAllNetworks()) {
                NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                        && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    @SuppressLint({"MissingPermission", "HardwareIds"})
    static JSONObject capture(Context context) {
        JSONObject root = new JSONObject();
        JsonUtil.put(root, "capturedAt", JsonUtil.now());
        JsonUtil.put(root, "platform", "android");
        JsonUtil.put(root, "operatingSystem", "Android " + Build.VERSION.RELEASE);
        JsonUtil.put(root, "operatingSystemVersion", Build.VERSION.RELEASE);
        JsonUtil.put(root, "androidApiLevel", Build.VERSION.SDK_INT);
        JsonUtil.put(root, "applicationVersion", BuildConfig.VERSION_NAME);
        JsonUtil.put(root, "device", captureDevice(context));

        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        Network active = manager == null ? null : manager.getActiveNetwork();
        NetworkCapabilities capabilities = manager == null || active == null ? null : manager.getNetworkCapabilities(active);
        LinkProperties links = manager == null || active == null ? null : manager.getLinkProperties(active);

        JSONObject connectivity = new JSONObject();
        JsonUtil.put(connectivity, "activeNetworkPresent", active != null);
        JsonUtil.put(connectivity, "activeNetworkHandle", active == null ? null : Long.toUnsignedString(active.getNetworkHandle()));
        JsonUtil.put(connectivity, "transports", transports(capabilities));
        JsonUtil.put(connectivity, "detectedAccessType", accessType(capabilities));
        JsonUtil.put(connectivity, "vpnActive", hasActiveVpn(context));
        JsonUtil.put(connectivity, "validated", has(capabilities, NetworkCapabilities.NET_CAPABILITY_VALIDATED));
        JsonUtil.put(connectivity, "captivePortal", has(capabilities, NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL));
        JsonUtil.put(connectivity, "internetCapability", has(capabilities, NetworkCapabilities.NET_CAPABILITY_INTERNET));
        JsonUtil.put(connectivity, "notRestricted", has(capabilities, NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED));
        if (Build.VERSION.SDK_INT >= 28) JsonUtil.put(connectivity, "notRoaming", has(capabilities, NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING));
        JsonUtil.put(connectivity, "metered", manager == null ? null : manager.isActiveNetworkMetered());
        JsonUtil.put(connectivity, "downstreamKbpsEstimate", capabilities == null ? null : capabilities.getLinkDownstreamBandwidthKbps());
        JsonUtil.put(connectivity, "upstreamKbpsEstimate", capabilities == null ? null : capabilities.getLinkUpstreamBandwidthKbps());
        JsonUtil.put(connectivity, "restrictBackgroundStatus", manager == null ? null : restrictBackground(manager.getRestrictBackgroundStatus()));
        JsonUtil.put(connectivity, "link", captureLinkProperties(links));
        JsonUtil.put(connectivity, "allNetworks", captureAllNetworks(manager));
        JsonUtil.put(root, "connectivity", connectivity);
        JsonUtil.put(root, "interfaces", captureInterfaces());
        JsonUtil.put(root, "wifi", captureWifi(context));
        JsonUtil.put(root, "cellular", captureCellular(context));
        JsonUtil.put(root, "deviceLocation", captureDeviceLocation(context));
        JsonUtil.put(root, "powerAndPolicy", capturePowerAndPolicy(context));
        JsonUtil.put(root, "limitations", new JSONArray()
                .put("Android exposes the active route, transports and radio summaries, but not upstream VLANs, carrier routing policy or the physical LTE tower location.")
                .put("SSID/BSSID and interface MAC values are hashed; subscriber identifiers, phone number, IMSI, ICCID and precise cell identity are never collected.")
                .put("When runtime permission is granted, deviceLocation contains a sensitive OS location fix with accuracy and age. It is separate from IP-prefix geolocation and is not proof of an LTE tower."));
        return root;
    }

    @SuppressLint("MissingPermission")
    private static JSONObject captureDeviceLocation(Context context) {
        JSONObject value = new JSONObject();
        boolean coarse = context.checkSelfPermission(android.Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        boolean fine = context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        JsonUtil.put(value, "permission", fine ? "fine" : coarse ? "coarse" : "denied");
        JsonUtil.put(value, "requestedBy", "user-initiated-network-test");
        JsonUtil.put(value, "sensitive", true);
        if (!coarse && !fine) {
            JsonUtil.put(value, "status", "permission-denied");
            JsonUtil.put(value, "limitation", "Android location permission was not granted; only IP-prefix geolocation is available.");
            return value;
        }
        LocationManager manager = context.getSystemService(LocationManager.class);
        if (manager == null) {
            JsonUtil.put(value, "status", "unavailable");
            JsonUtil.put(value, "limitation", "Android LocationManager is unavailable.");
            return value;
        }
        Location best = null;
        try {
            for (String provider : manager.getProviders(true)) {
                Location candidate = manager.getLastKnownLocation(provider);
                if (betterLocation(candidate, best)) best = candidate;
            }
            long ageMs = locationAgeMs(best);
            if (Build.VERSION.SDK_INT >= 30 && (best == null || ageMs > 120_000 || best.getAccuracy() > 200)) {
                String provider = preferredProvider(manager);
                if (provider != null) {
                    CountDownLatch latch = new CountDownLatch(1);
                    AtomicReference<Location> current = new AtomicReference<>();
                    CancellationSignal cancellation = new CancellationSignal();
                    ExecutorService executor = Executors.newSingleThreadExecutor();
                    try {
                        manager.getCurrentLocation(provider, cancellation, executor, location -> { current.set(location); latch.countDown(); });
                        latch.await(6, TimeUnit.SECONDS);
                    } finally {
                        cancellation.cancel(); executor.shutdownNow();
                    }
                    if (betterLocation(current.get(), best)) best = current.get();
                }
            }
        } catch (SecurityException error) {
            JsonUtil.put(value, "status", "permission-denied");
            JsonUtil.put(value, "error", "Location permission changed during capture.");
            return value;
        } catch (Exception error) {
            JsonUtil.put(value, "captureError", JsonUtil.redact(error.getClass().getSimpleName()));
        }
        if (best == null) {
            JsonUtil.put(value, "status", "unavailable");
            JsonUtil.put(value, "locationServicesEnabled", Build.VERSION.SDK_INT < 28 || manager.isLocationEnabled());
            JsonUtil.put(value, "limitation", "No current or cached OS location fix was available.");
            return value;
        }
        JsonUtil.put(value, "status", "observed");
        JsonUtil.put(value, "latitude", round(best.getLatitude(), 6));
        JsonUtil.put(value, "longitude", round(best.getLongitude(), 6));
        JsonUtil.put(value, "accuracyMeters", round(best.getAccuracy(), 1));
        if (best.hasAltitude()) JsonUtil.put(value, "altitudeMeters", round(best.getAltitude(), 1));
        JsonUtil.put(value, "provider", best.getProvider());
        JsonUtil.put(value, "capturedAtEpochMs", best.getTime());
        JsonUtil.put(value, "ageMsAtCapture", locationAgeMs(best));
        JsonUtil.put(value, "mock", Build.VERSION.SDK_INT >= 31 ? best.isMock() : best.isFromMockProvider());
        JsonUtil.put(value, "confidence", best.getAccuracy() <= 100 ? "high-os-location" : best.getAccuracy() <= 1000 ? "medium-os-location" : "low-os-location");
        JsonUtil.put(value, "limitation", "This is a device position supplied by Android; it can be cached, inferred, or mocked and does not locate the router, proxy endpoint, or LTE cell.");
        return value;
    }

    private static String preferredProvider(LocationManager manager) {
        List<String> enabled = manager.getProviders(true);
        if (Build.VERSION.SDK_INT >= 31 && enabled.contains(LocationManager.FUSED_PROVIDER)) return LocationManager.FUSED_PROVIDER;
        if (enabled.contains(LocationManager.GPS_PROVIDER)) return LocationManager.GPS_PROVIDER;
        if (enabled.contains(LocationManager.NETWORK_PROVIDER)) return LocationManager.NETWORK_PROVIDER;
        return enabled.isEmpty() ? null : enabled.get(0);
    }

    private static boolean betterLocation(Location candidate, Location current) {
        if (candidate == null) return false;
        if (current == null) return true;
        long candidateAge = locationAgeMs(candidate), currentAge = locationAgeMs(current);
        if (candidateAge + 120_000 < currentAge) return true;
        if (currentAge + 120_000 < candidateAge) return false;
        return candidate.getAccuracy() < current.getAccuracy();
    }

    private static long locationAgeMs(Location location) {
        if (location == null) return Long.MAX_VALUE;
        if (location.getElapsedRealtimeNanos() > 0) return Math.max(0, (SystemClock.elapsedRealtimeNanos() - location.getElapsedRealtimeNanos()) / 1_000_000L);
        return Math.max(0, System.currentTimeMillis() - location.getTime());
    }

    private static double round(double value, int digits) {
        double scale = Math.pow(10, digits); return Math.round(value * scale) / scale;
    }

    private static JSONObject captureDevice(Context context) {
        JSONObject value = new JSONObject();
        JsonUtil.put(value, "manufacturer", Build.MANUFACTURER);
        JsonUtil.put(value, "brand", Build.BRAND);
        JsonUtil.put(value, "model", Build.MODEL);
        JsonUtil.put(value, "device", Build.DEVICE);
        JsonUtil.put(value, "product", Build.PRODUCT);
        JsonUtil.put(value, "hardware", Build.HARDWARE);
        JsonUtil.put(value, "supportedAbis", JsonUtil.array(java.util.Arrays.asList(Build.SUPPORTED_ABIS)));
        JsonUtil.put(value, "androidRelease", Build.VERSION.RELEASE);
        JsonUtil.put(value, "apiLevel", Build.VERSION.SDK_INT);
        JsonUtil.put(value, "securityPatch", Build.VERSION.SECURITY_PATCH);
        JsonUtil.put(value, "buildFingerprintSha256", hash(Build.FINGERPRINT));
        JsonUtil.put(value, "kernel", System.getProperty("os.version"));
        JsonUtil.put(value, "locale", Locale.getDefault().toLanguageTag());
        JsonUtil.put(value, "timeZone", ZoneId.systemDefault().getId());
        ActivityManager activity = context.getSystemService(ActivityManager.class);
        if (activity != null) {
            ActivityManager.MemoryInfo memory = new ActivityManager.MemoryInfo();
            activity.getMemoryInfo(memory);
            JsonUtil.put(value, "memoryClassMiB", activity.getMemoryClass());
            JsonUtil.put(value, "lowMemory", memory.lowMemory);
            JsonUtil.put(value, "availableMemoryMiB", memory.availMem / 1024 / 1024);
        }
        return value;
    }

    private static JSONObject captureLinkProperties(LinkProperties links) {
        if (links == null) return null;
        JSONObject value = new JSONObject();
        JsonUtil.put(value, "interfaceName", links.getInterfaceName());
        JsonUtil.put(value, "domains", links.getDomains());
        if (Build.VERSION.SDK_INT >= 29) JsonUtil.put(value, "mtu", links.getMtu());
        JSONArray addresses = new JSONArray();
        for (LinkAddress address : links.getLinkAddresses()) addresses.put(address.toString());
        JsonUtil.put(value, "addresses", addresses);
        JSONArray dns = new JSONArray();
        for (InetAddress address : links.getDnsServers()) dns.put(address.getHostAddress());
        JsonUtil.put(value, "dnsServers", dns);
        JSONArray routes = new JSONArray();
        for (RouteInfo route : links.getRoutes()) {
            JSONObject item = new JSONObject();
            JsonUtil.put(item, "destination", route.getDestination() == null ? null : route.getDestination().toString());
            JsonUtil.put(item, "gateway", route.getGateway() == null ? null : route.getGateway().getHostAddress());
            JsonUtil.put(item, "interface", route.getInterface());
            JsonUtil.put(item, "defaultRoute", route.isDefaultRoute());
            routes.put(item);
        }
        JsonUtil.put(value, "routes", routes);
        ProxyInfo proxy = links.getHttpProxy();
        if (proxy != null) {
            JSONObject proxyValue = new JSONObject();
            JsonUtil.put(proxyValue, "host", proxy.getHost());
            JsonUtil.put(proxyValue, "port", proxy.getPort());
            JsonUtil.put(proxyValue, "pacUrlPresent", proxy.getPacFileUrl() != null && !proxy.getPacFileUrl().toString().trim().isEmpty());
            JsonUtil.put(value, "httpProxy", proxyValue);
        }
        if (Build.VERSION.SDK_INT >= 28) {
            JsonUtil.put(value, "privateDnsActive", links.isPrivateDnsActive());
            JsonUtil.put(value, "privateDnsServerName", links.getPrivateDnsServerName());
        }
        if (Build.VERSION.SDK_INT >= 30 && links.getNat64Prefix() != null) JsonUtil.put(value, "nat64Prefix", links.getNat64Prefix().toString());
        return value;
    }

    private static JSONArray captureAllNetworks(ConnectivityManager manager) {
        JSONArray result = new JSONArray();
        if (manager == null) return result;
        try {
            for (Network network : manager.getAllNetworks()) {
                JSONObject item = new JSONObject();
                NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
                LinkProperties links = manager.getLinkProperties(network);
                JsonUtil.put(item, "handle", Long.toUnsignedString(network.getNetworkHandle()));
                JsonUtil.put(item, "transports", transports(capabilities));
                JsonUtil.put(item, "interfaceName", links == null ? null : links.getInterfaceName());
                JsonUtil.put(item, "validated", has(capabilities, NetworkCapabilities.NET_CAPABILITY_VALIDATED));
                JsonUtil.put(item, "vpn", capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
                result.put(item);
            }
        } catch (Exception error) {
            JSONObject item = new JSONObject(); JsonUtil.put(item, "error", JsonUtil.redact(error.getMessage())); result.put(item);
        }
        return result;
    }

    private static JSONArray captureInterfaces() {
        JSONArray result = new JSONArray();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) return result;
            for (NetworkInterface network : Collections.list(interfaces)) {
                JSONObject item = new JSONObject();
                JsonUtil.put(item, "name", network.getName());
                JsonUtil.put(item, "displayName", network.getDisplayName());
                JsonUtil.put(item, "up", network.isUp());
                JsonUtil.put(item, "loopback", network.isLoopback());
                JsonUtil.put(item, "pointToPoint", network.isPointToPoint());
                JsonUtil.put(item, "virtual", network.isVirtual());
                JsonUtil.put(item, "mtu", network.getMTU());
                byte[] mac = network.getHardwareAddress();
                JsonUtil.put(item, "macSha256", mac == null ? null : hash(bytesHex(mac)));
                JSONArray addresses = new JSONArray();
                for (InetAddress address : Collections.list(network.getInetAddresses())) addresses.put(address.getHostAddress());
                JsonUtil.put(item, "addresses", addresses);
                result.put(item);
            }
        } catch (Exception error) {
            JSONObject item = new JSONObject(); JsonUtil.put(item, "error", JsonUtil.redact(error.getMessage())); result.put(item);
        }
        return result;
    }

    @SuppressLint({"MissingPermission", "HardwareIds"})
    private static JSONObject captureWifi(Context context) {
        JSONObject value = new JSONObject();
        WifiManager manager = context.getApplicationContext().getSystemService(WifiManager.class);
        if (manager == null) return value;
        JsonUtil.put(value, "wifiEnabled", manager.isWifiEnabled());
        try {
            WifiInfo info = manager.getConnectionInfo();
            if (info != null) {
                String ssid = info.getSSID();
                String bssid = info.getBSSID();
                JsonUtil.put(value, "ssidSha256", ssid == null || "<unknown ssid>".equalsIgnoreCase(ssid) ? null : hash(ssid));
                JsonUtil.put(value, "bssidSha256", bssid == null || "02:00:00:00:00:00".equals(bssid) ? null : hash(bssid));
                JsonUtil.put(value, "rssiDbm", info.getRssi());
                JsonUtil.put(value, "signalLevel0To4", WifiManager.calculateSignalLevel(info.getRssi(), 5));
                JsonUtil.put(value, "linkSpeedMbps", info.getLinkSpeed());
                JsonUtil.put(value, "frequencyMhz", info.getFrequency());
                if (Build.VERSION.SDK_INT >= 29) {
                    JsonUtil.put(value, "rxLinkSpeedMbps", info.getRxLinkSpeedMbps());
                    JsonUtil.put(value, "txLinkSpeedMbps", info.getTxLinkSpeedMbps());
                }
                if (Build.VERSION.SDK_INT >= 30) JsonUtil.put(value, "wifiStandard", wifiStandard(info.getWifiStandard()));
                if (Build.VERSION.SDK_INT >= 31) JsonUtil.put(value, "securityType", info.getCurrentSecurityType());
            }
            DhcpInfo dhcp = manager.getDhcpInfo();
            if (dhcp != null) {
                JSONObject dhcpValue = new JSONObject();
                JsonUtil.put(dhcpValue, "ipAddress", ipv4(dhcp.ipAddress));
                JsonUtil.put(dhcpValue, "gateway", ipv4(dhcp.gateway));
                JsonUtil.put(dhcpValue, "netmask", ipv4(dhcp.netmask));
                JsonUtil.put(dhcpValue, "dns1", ipv4(dhcp.dns1));
                JsonUtil.put(dhcpValue, "dns2", ipv4(dhcp.dns2));
                JsonUtil.put(dhcpValue, "leaseDurationSeconds", dhcp.leaseDuration);
                JsonUtil.put(value, "dhcp", dhcpValue);
            }
        } catch (SecurityException error) {
            JsonUtil.put(value, "permissionError", "Wi-Fi details require Nearby devices/location permission.");
        } catch (Exception error) {
            JsonUtil.put(value, "error", JsonUtil.redact(error.getMessage()));
        }
        return value;
    }

    @SuppressLint("MissingPermission")
    private static JSONObject captureCellular(Context context) {
        JSONObject value = new JSONObject();
        TelephonyManager manager = context.getSystemService(TelephonyManager.class);
        if (manager == null) return value;
        try {
            JsonUtil.put(value, "phoneType", manager.getPhoneType());
            JsonUtil.put(value, "networkOperatorName", manager.getNetworkOperatorName());
            JsonUtil.put(value, "simOperatorName", manager.getSimOperatorName());
            JsonUtil.put(value, "networkCountryIso", manager.getNetworkCountryIso());
            JsonUtil.put(value, "simCountryIso", manager.getSimCountryIso());
            JsonUtil.put(value, "networkRoaming", manager.isNetworkRoaming());
            JsonUtil.put(value, "dataNetworkType", networkType(manager.getDataNetworkType()));
            JsonUtil.put(value, "voiceNetworkType", networkType(manager.getVoiceNetworkType()));
            JsonUtil.put(value, "dataEnabled", manager.isDataEnabled());
            if (Build.VERSION.SDK_INT >= 29 && manager.getSignalStrength() != null) {
                JSONArray signals = new JSONArray();
                for (CellSignalStrength signal : manager.getSignalStrength().getCellSignalStrengths()) {
                    JSONObject item = new JSONObject();
                    JsonUtil.put(item, "radioClass", signal.getClass().getSimpleName());
                    JsonUtil.put(item, "dbm", signal.getDbm());
                    JsonUtil.put(item, "asuLevel", signal.getAsuLevel());
                    JsonUtil.put(item, "level0To4", signal.getLevel());
                    signals.put(item);
                }
                JsonUtil.put(value, "signalStrengths", signals);
            } else if (Build.VERSION.SDK_INT >= 28 && manager.getSignalStrength() != null) {
                JsonUtil.put(value, "aggregateSignalLevel0To4", manager.getSignalStrength().getLevel());
            }
            JSONArray cells = new JSONArray();
            List<CellInfo> allCells = manager.getAllCellInfo();
            if (allCells != null) for (CellInfo cell : allCells) {
                JSONObject item = new JSONObject();
                JsonUtil.put(item, "radioClass", cell.getClass().getSimpleName());
                JsonUtil.put(item, "registered", cell.isRegistered());
                JsonUtil.put(item, "timestampMillis", cell.getTimeStamp() / 1_000_000L);
                JsonUtil.put(item, "cellIdentityCollected", false);
                cells.put(item);
            }
            JsonUtil.put(value, "visibleCellSummaries", cells);
            SubscriptionManager subscriptions = context.getSystemService(SubscriptionManager.class);
            JSONArray sims = new JSONArray();
            if (subscriptions != null) {
                List<SubscriptionInfo> active = subscriptions.getActiveSubscriptionInfoList();
                if (active != null) for (SubscriptionInfo subscription : active) {
                    JSONObject item = new JSONObject();
                    JsonUtil.put(item, "simSlotIndex", subscription.getSimSlotIndex());
                    JsonUtil.put(item, "carrierName", subscription.getCarrierName() == null ? null : subscription.getCarrierName().toString());
                    JsonUtil.put(item, "countryIso", subscription.getCountryIso());
                    if (Build.VERSION.SDK_INT >= 29) {
                        JsonUtil.put(item, "mcc", subscription.getMccString());
                        JsonUtil.put(item, "mnc", subscription.getMncString());
                        JsonUtil.put(item, "embedded", subscription.isEmbedded());
                        JsonUtil.put(item, "opportunistic", subscription.isOpportunistic());
                    } else {
                        JsonUtil.put(item, "mcc", subscription.getMcc());
                        JsonUtil.put(item, "mnc", subscription.getMnc());
                    }
                    sims.put(item);
                }
            }
            JsonUtil.put(value, "activeSubscriptions", sims);
        } catch (SecurityException error) {
            JsonUtil.put(value, "permissionError", "Phone/location permission was not granted; subscriber identifiers are never requested.");
        } catch (Exception error) {
            JsonUtil.put(value, "error", JsonUtil.redact(error.getMessage()));
        }
        return value;
    }

    private static JSONObject capturePowerAndPolicy(Context context) {
        JSONObject value = new JSONObject();
        PowerManager power = context.getSystemService(PowerManager.class);
        BatteryManager battery = context.getSystemService(BatteryManager.class);
        JsonUtil.put(value, "powerSaveMode", power == null ? null : power.isPowerSaveMode());
        JsonUtil.put(value, "deviceIdleMode", power == null ? null : power.isDeviceIdleMode());
        JsonUtil.put(value, "batteryPercent", battery == null ? null : battery.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY));
        JsonUtil.put(value, "airplaneMode", Settings.Global.getInt(context.getContentResolver(), Settings.Global.AIRPLANE_MODE_ON, 0) != 0);
        JsonUtil.put(value, "automaticTime", Settings.Global.getInt(context.getContentResolver(), Settings.Global.AUTO_TIME, 0) != 0);
        JsonUtil.put(value, "automaticTimeZone", Settings.Global.getInt(context.getContentResolver(), Settings.Global.AUTO_TIME_ZONE, 0) != 0);
        return value;
    }

    private static boolean has(NetworkCapabilities capabilities, int capability) {
        return capabilities != null && capabilities.hasCapability(capability);
    }

    private static JSONArray transports(NetworkCapabilities capabilities) {
        JSONArray result = new JSONArray();
        if (capabilities == null) return result;
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) result.put("wifi");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) result.put("cellular");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) result.put("ethernet");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) result.put("vpn");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) result.put("bluetooth");
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE)) result.put("wifi-aware");
        if (Build.VERSION.SDK_INT >= 31 && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_USB)) result.put("usb");
        return result;
    }

    private static String accessType(NetworkCapabilities capabilities) {
        if (capabilities == null) return "offline-or-unknown";
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "vpn";
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "cellular";
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi";
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "ethernet";
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) return "bluetooth-tethering";
        if (Build.VERSION.SDK_INT >= 31 && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_USB)) return "usb";
        return "other";
    }

    private static String restrictBackground(int value) {
        if (value == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED) return "enabled";
        if (value == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED) return "whitelisted";
        return "disabled";
    }

    private static String wifiStandard(int standard) {
        switch (standard) {
            case ScanResult.WIFI_STANDARD_LEGACY: return "legacy";
            case ScanResult.WIFI_STANDARD_11N: return "802.11n/Wi-Fi 4";
            case ScanResult.WIFI_STANDARD_11AC: return "802.11ac/Wi-Fi 5";
            case ScanResult.WIFI_STANDARD_11AX: return "802.11ax/Wi-Fi 6";
            case ScanResult.WIFI_STANDARD_11AD: return "802.11ad/WiGig";
            default: return "unknown(" + standard + ")";
        }
    }

    private static String networkType(int type) {
        switch (type) {
            case TelephonyManager.NETWORK_TYPE_GPRS: return "GPRS/2G";
            case TelephonyManager.NETWORK_TYPE_EDGE: return "EDGE/2G";
            case TelephonyManager.NETWORK_TYPE_UMTS: return "UMTS/3G";
            case TelephonyManager.NETWORK_TYPE_HSDPA:
            case TelephonyManager.NETWORK_TYPE_HSUPA:
            case TelephonyManager.NETWORK_TYPE_HSPA:
            case TelephonyManager.NETWORK_TYPE_HSPAP: return "HSPA/3G";
            case TelephonyManager.NETWORK_TYPE_CDMA:
            case TelephonyManager.NETWORK_TYPE_1xRTT:
            case TelephonyManager.NETWORK_TYPE_EVDO_0:
            case TelephonyManager.NETWORK_TYPE_EVDO_A:
            case TelephonyManager.NETWORK_TYPE_EVDO_B: return "CDMA/EVDO";
            case TelephonyManager.NETWORK_TYPE_LTE: return "LTE/4G";
            case TelephonyManager.NETWORK_TYPE_NR: return "NR/5G";
            case TelephonyManager.NETWORK_TYPE_IWLAN: return "IWLAN";
            case TelephonyManager.NETWORK_TYPE_UNKNOWN: return "unknown";
            default: return "type-" + type;
        }
    }

    private static String ipv4(int value) {
        return String.format(Locale.ROOT, "%d.%d.%d.%d", value & 0xff, value >> 8 & 0xff, value >> 16 & 0xff, value >> 24 & 0xff);
    }

    private static String hash(String value) {
        if (value == null) return null;
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return bytesHex(digest);
        } catch (Exception ignored) { return null; }
    }

    private static String bytesHex(byte[] bytes) {
        StringBuilder value = new StringBuilder();
        for (byte b : bytes) value.append(String.format(Locale.ROOT, "%02x", b));
        return value.toString();
    }
}
