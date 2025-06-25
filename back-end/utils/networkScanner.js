const nmap = require('node-nmap');
const os = require('os');

// Enhanced device fingerprinting database (keeping your original working patterns)
const DEVICE_SIGNATURES = {
    // Nintendo devices
    nintendo: {
        patterns: [
            { vendor: /nintendo/i, ports: [22, 80], name: "Nintendo Switch" },
            { vendor: /nintendo/i, ports: [1024, 6667], name: "Nintendo 3DS" },
            { vendor: /nintendo/i, ports: [80, 443], name: "Nintendo Wii U" }
        ]
    },
    
    // Apple devices
    apple: {
        patterns: [
            { vendor: /apple/i, ports: [22, 62078], name: "iPhone/iPad" },
            { vendor: /apple/i, ports: [22, 88, 548, 631], name: "MacBook/iMac" },
            { vendor: /apple/i, ports: [3689, 5000, 7000], name: "Apple TV" },
            { vendor: /apple/i, ports: [80, 443, 10001], name: "HomePod" }
        ]
    },
    
    // Smart TVs
    tv: {
        patterns: [
            { vendor: /samsung/i, ports: [8001, 8002], name: "Samsung Smart TV" },
            { vendor: /lg/i, ports: [3000, 3001], name: "LG Smart TV" },
            { vendor: /sony/i, ports: [80, 20060], name: "Sony Smart TV" },
            { vendor: /roku/i, ports: [8060, 8080], name: "Roku TV/Device" },
            { vendor: /amazon/i, ports: [8080, 9080], name: "Amazon Fire TV" }
        ]
    },
    
    // Printers
    printers: {
        patterns: [
            { vendor: /hp|hewlett/i, ports: [631, 9100], name: "HP Printer" },
            { vendor: /canon/i, ports: [631, 8610], name: "Canon Printer" },
            { vendor: /brother/i, ports: [631, 9100], name: "Brother Printer" },
            { vendor: /epson/i, ports: [631, 9100], name: "Epson Printer" }
        ]
    },
    
    // Smart home devices
    smarthome: {
        patterns: [
            { vendor: /amazon/i, ports: [443, 4070], name: "Amazon Echo/Alexa" },
            { vendor: /google/i, ports: [8008, 8009], name: "Google Home/Nest" },
            { vendor: /philips/i, ports: [80, 443], name: "Philips Hue Bridge" },
            { vendor: /nest/i, ports: [443, 9543], name: "Nest Thermostat" },
            { vendor: /ring/i, ports: [443, 1935], name: "Ring Doorbell/Camera" }
        ]
    },
    
    // Routers and networking
    networking: {
        patterns: [
            { vendor: /netgear/i, ports: [80, 443, 53], name: "Netgear Router" },
            { vendor: /linksys/i, ports: [80, 443], name: "Linksys Router" },
            { vendor: /asus/i, ports: [80, 443, 8080], name: "ASUS Router" },
            { vendor: /tplink|tp-link/i, ports: [80, 443], name: "TP-Link Router" },
            { vendor: /ubiquiti/i, ports: [22, 80, 443], name: "Ubiquiti Access Point" }
        ]
    },
    
    // Gaming consoles
    gaming: {
        patterns: [
            { vendor: /sony/i, ports: [80, 443, 9293], name: "PlayStation Console" },
            { vendor: /microsoft/i, ports: [53, 88, 3074], name: "Xbox Console" },
            { vendor: /valve/i, ports: [27015, 27036], name: "Steam Deck/Link" }
        ]
    }
};

// Enhanced MAC address vendor database (keeping your original + adding more)
const MAC_VENDORS = {
    "00:0C:F1": "Intel Corporation",
    "00:16:CB": "Apple Inc",
    "00:1B:63": "Apple Inc", 
    "00:50:C2": "Apple Inc",
    "00:21:E9": "Dell Inc",
    "00:26:BB": "Apple Inc",
    "B8:8D:12": "Apple Inc",
    "3C:07:54": "Apple Inc",
    "E8:2A:EA": "Apple Inc",
    "00:22:58": "NETGEAR Inc",
    "00:26:F2": "NETGEAR Inc",
    "A0:63:91": "NETGEAR Inc",
    "00:04:20": "Linksys LLC",
    "00:18:39": "Linksys LLC",
    "48:F8:B3": "Linksys LLC",
    "00:0F:66": "Linksys LLC",
    "00:1E:58": "ASUS",
    "04:D4:C4": "ASUS",
    "2C:56:DC": "ASUS",
    "00:17:3F": "Belkin International Inc",
    "94:44:52": "Belkin International Inc",
    "00:23:69": "Cisco Systems",
    "00:1B:D5": "Hewlett Packard",
    "00:1F:29": "Hewlett Packard",
    "70:5A:0F": "Hewlett Packard Enterprise",
    "00:0A:E4": "Brother Industries",
    "00:80:77": "Brother Industries",
    "00:50:04": "Canon Inc",
    "00:26:67": "Canon Inc",
    "00:00:48": "EPSON",
    "04:4F:AA": "EPSON",
    "00:50:C2": "Samsung Electronics",
    "28:CD:C1": "Samsung Electronics",
    "E8:50:8B": "Samsung Electronics",
    "00:09:BF": "LG Electronics",
    "20:64:32": "LG Electronics",
    "60:6B:BD": "LG Electronics",
    "00:50:C2": "Nintendo Co Ltd",
    "00:17:AB": "Nintendo Co Ltd",
    "00:19:1D": "Nintendo Co Ltd",
    "00:22:D9": "Nintendo Co Ltd",
    "00:24:F3": "Nintendo Co Ltd",
    "A4:C0:E1": "Nintendo Co Ltd",
    "B8:AE:6E": "Nintendo Co Ltd",
    "00:0D:3A": "Microsoft Corporation",
    "00:50:F2": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "7C:ED:8D": "Microsoft Corporation",
    "00:08:A1": "Sony Corporation",
    "00:04:1F": "Sony Corporation",
    "84:17:66": "Sony Corporation",
    "FC:0F:E6": "Sony Corporation",
    "00:50:C2": "Amazon Technologies Inc",
    "44:65:0D": "Amazon Technologies Inc",
    "F0:D2:F1": "Amazon Technologies Inc",
    "50:DC:E7": "Amazon Technologies Inc",
    
    // Additional vendors for better detection - EXPANDED 2025 DATABASE
    "B8:27:EB": "Raspberry Pi Trading",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "52:54:00": "QEMU Virtual Network",
    "08:00:27": "Oracle VirtualBox",
    "00:0C:29": "VMware Inc",
    "00:50:56": "VMware Inc",
    "18:B4:30": "Nest Labs Inc",
    "64:16:66": "Nest Labs Inc",
    "00:07:7D": "Roku Inc",
    "DC:3A:5E": "Roku Inc",
    "00:12:12": "Hikvision",
    "BC:AD:28": "Hikvision",
    "00:23:8B": "Dahua Technology",
    
    // IoT Device Manufacturers (the ones you're seeing as Unknown)
    "C4:4E:AC": "Shenzhen Shiningworth Technology",
    "F4:B8:5E": "Texas Instruments",
    "EC:6C:9A": "Arcadyan",
    "C0:B5:D7": "Chongqing Fugui Electronics", 
    "C0:E7:BF": "Sichuan AI-Link Technology",
    "00:80:92": "Silex Technology",
    
    // More IoT and embedded system manufacturers
    "24:0A:C4": "Espressif Inc",
    "CC:50:E3": "Espressif Inc", 
    "84:0D:8E": "Espressif Inc",
    "30:AE:A4": "Espressif Inc",
    "A4:CF:12": "Espressif Inc",
    "B4:E6:2D": "Espressif Inc",
    "DC:4F:22": "Espressif Inc",
    "E8:DB:84": "Espressif Inc",
    "EC:62:60": "Espressif Inc",
    "5C:CF:7F": "Espressif Inc",
    
    // Texas Instruments variations (very common in IoT)
    "00:12:4B": "Texas Instruments",
    "04:79:70": "Texas Instruments", 
    "68:C9:0B": "Texas Instruments",
    "88:C2:55": "Texas Instruments",
    "B0:B4:48": "Texas Instruments",
    "F0:F0:0C": "Texas Instruments",
    "F4:B8:5E": "Texas Instruments",
    
    // Arcadyan (router/gateway manufacturer)
    "00:1D:19": "Arcadyan Corporation",
    "00:22:2D": "Arcadyan Corporation", 
    "00:8C:54": "Arcadyan Corporation",
    "88:25:2C": "Arcadyan Corporation",
    "EC:6C:9A": "Arcadyan Corporation",
    "F8:8E:85": "Arcadyan Corporation",
    
    // Chinese IoT manufacturers
    "8C:AA:B5": "Shenzhen Ogemray Technology",
    "C8:2B:96": "Shenzhen Ogemray Technology", 
    "20:6B:E7": "Hangzhou Hikvision",
    "C0:B5:D7": "Chongqing Fugui Electronics",
    "C0:E7:BF": "Sichuan AI-Link Technology",
    "00:80:92": "Silex Technology",
    "C4:4E:AC": "Shenzhen Shiningworth Technology",
    
    // More common device manufacturers
    "6C:AD:F8": "AzureWave Technology Inc",
    "90:84:0D": "AzureWave Technology Inc",
    "00:E0:4C": "Realtek Semiconductor Co",
    "52:54:00": "QEMU Virtual Network",
    "08:00:27": "Oracle VirtualBox",
    "00:25:9C": "Cisco Systems Inc",
    "00:26:CA": "Cisco Systems Inc",
    "00:40:96": "Cisco Systems Inc",
    "14:69:E2": "Cisco Systems Inc",
    "28:C7:CE": "Cisco Systems Inc",
    "3C:CE:73": "Cisco Systems Inc",
    "68:BD:AB": "Cisco Systems Inc",
    "7C:95:F3": "Cisco Systems Inc",
    "A0:23:9F": "Cisco Systems Inc",
    "C8:00:84": "Cisco Systems Inc",
    
    // Mediatek (common in IoT devices)
    "14:DD:A9": "MediaTek Inc",
    "BC:F5:AC": "MediaTek Inc",
    "DC:EF:CA": "MediaTek Inc",
    "E0:19:1D": "MediaTek Inc",
    
    // Broadcom (WiFi chips)
    "00:10:18": "Broadcom Corporation",
    "00:90:4C": "Broadcom Corporation",
    "B4:99:BA": "Broadcom Corporation",
    "CC:B2:55": "Broadcom Corporation",
    
    // Qualcomm (mobile devices)
    "00:0A:F5": "Qualcomm Inc",
    "30:39:26": "Qualcomm Inc",
    "58:A2:B5": "Qualcomm Inc",
    "98:5F:D3": "Qualcomm Inc",
    
    // More smart device manufacturers
    "F4:F5:D8": "Google Inc",
    "AC:BC:32": "Google Inc",
    "F8:8F:CA": "Google Inc",
    "CC:50:E3": "Google Inc",
    "F0:EF:86": "Google Inc",
    "DA:A1:19": "Google Inc",
    
    // Additional Apple variations
    "8C:85:90": "Apple Inc",
    "A4:83:E7": "Apple Inc",
    "BC:52:B7": "Apple Inc",
    "F0:18:98": "Apple Inc",
    "F4:37:B7": "Apple Inc",
    
    // TP-Link variations
    "50:C7:BF": "TP-LINK Technologies Co Ltd",
    "A4:2B:8C": "TP-LINK Technologies Co Ltd",
    "C0:25:E9": "TP-LINK Technologies Co Ltd",
    "E8:DE:27": "TP-LINK Technologies Co Ltd",
    "EC:08:6B": "TP-LINK Technologies Co Ltd",
    
    // D-Link
    "00:05:5D": "D-Link Corporation",
    "00:0F:3D": "D-Link Corporation",
    "00:13:46": "D-Link Corporation",
    "00:17:9A": "D-Link Corporation",
    "00:19:5B": "D-Link Corporation",
    "00:1B:11": "D-Link Corporation",
    "00:1C:F0": "D-Link Corporation",
    "00:1E:58": "D-Link Corporation",
    "00:21:91": "D-Link Corporation",
    "00:22:B0": "D-Link Corporation",
    "00:24:01": "D-Link Corporation",
    "00:26:5A": "D-Link Corporation",
    "14:D6:4D": "D-Link Corporation",
    "1C:7E:E5": "D-Link Corporation",
    "20:CF:30": "D-Link Corporation",
    "24:05:0F": "D-Link Corporation",
    "28:10:7B": "D-Link Corporation",
    "2C:B0:5D": "D-Link Corporation",
    "34:08:04": "D-Link Corporation",
    "40:61:86": "D-Link Corporation",
    "54:B8:0A": "D-Link Corporation",
    "5C:F4:AB": "D-Link Corporation",
    "60:E3:27": "D-Link Corporation",
    "78:54:2E": "D-Link Corporation",
    "84:C9:B2": "D-Link Corporation",
    "90:94:E4": "D-Link Corporation",
    "C0:A0:BB": "D-Link Corporation",
    "CC:B2:55": "D-Link Corporation",
    "E4:6F:13": "D-Link Corporation",
    "F0:7D:68": "D-Link Corporation"
};

// Service identification patterns
const SERVICE_PATTERNS = {
    21: "FTP Server",
    22: "SSH Server",
    23: "Telnet Server", 
    25: "SMTP Mail Server",
    53: "DNS Server",
    80: "HTTP Web Server",
    110: "POP3 Mail Server",
    143: "IMAP Mail Server",
    443: "HTTPS Web Server",
    993: "IMAPS Secure Mail",
    995: "POP3S Secure Mail",
    631: "IPP Printer",
    9100: "Raw Printer Port",
    8080: "HTTP Alternate/Proxy",
    3389: "Windows Remote Desktop",
    5900: "VNC Remote Desktop",
    1900: "UPnP Discovery",
    8008: "Chromecast/Google Cast",
    8009: "Chromecast/Google Cast SSL",
    3000: "LG webOS TV",
    8001: "Samsung TV Remote Control",
    8002: "Samsung TV Secure Remote",
    62078: "iOS Device (Apple)",
    5000: "AirPlay (Apple)",
    7000: "AirPlay (Apple)",
    3689: "iTunes DAAP",
    10001: "Apple TV Control"
};

// Operating System detection patterns
const OS_PATTERNS = {
    windows: {
        ports: [135, 139, 445, 3389],
        services: ["microsoft-ds", "netbios-ssn", "ms-wbt-server"],
        name: "Windows"
    },
    macos: {
        ports: [22, 548, 631, 5000, 62078],
        services: ["ssh", "afp", "ipp", "airplay"],
        name: "macOS"
    },
    linux: {
        ports: [22, 80, 443],
        services: ["ssh", "http", "https"],
        name: "Linux"
    },
    ios: {
        ports: [62078, 5000, 7000],
        services: ["lockdown", "airplay"],
        name: "iOS"
    },
    android: {
        ports: [5555, 8080],
        services: ["adb", "http-alt"],
        name: "Android"
    }
};

// Get current network information
function getNetworkInfo() {
    return new Promise((resolve, reject) => {
        try {
            console.log('📡 Detecting network interfaces...');
            const interfaces = os.networkInterfaces();
            let networkInfo = null;

            for (const [name, networks] of Object.entries(interfaces)) {
                for (const network of networks) {
                    if (!network.internal && network.family === 'IPv4') {
                        const ip = network.address;
                        const netmask = network.netmask;
                        
                        const ipParts = ip.split('.');
                        const subnetBase = ipParts[0] + '.' + ipParts[1] + '.' + ipParts[2] + '.0/24';
                        
                        networkInfo = {
                            interface: name,
                            ip: ip,
                            netmask: netmask,
                            subnet: subnetBase
                        };
                        
                        console.log('✅ Found active interface: ' + name + ' (' + ip + ')');
                        break;
                    }
                }
                if (networkInfo) break;
            }

            if (!networkInfo) {
                reject(new Error('No active network interface found'));
            } else {
                resolve(networkInfo);
            }
        } catch (error) {
            reject(error);
        }
    });
}

// Enhanced MAC vendor lookup
function getVendorFromMAC(mac) {
    if (!mac || mac === 'Unknown') return 'Unknown';
    
    const oui = mac.substring(0, 8).toUpperCase();
    const vendor = MAC_VENDORS[oui];
    
    if (vendor) {
        return vendor;
    }
    
    // Try with different MAC format variations
    const cleanMac = mac.replace(/[:-]/g, '').toUpperCase();
    const formattedOui = cleanMac.substring(0, 6);
    
    for (const [ouiKey, vendorName] of Object.entries(MAC_VENDORS)) {
        const cleanOui = ouiKey.replace(/[:-]/g, '');
        if (formattedOui.startsWith(cleanOui)) {
            return vendorName;
        }
    }
    
    return 'Unknown Vendor';
}

// Enhanced device identification (keeping your working logic)
function identifyDevice(device) {
    const vendor = device.vendor || 'Unknown';
    const hostname = device.hostname || 'Unknown';
    const openPorts = device.openPorts || [];
    const mac = device.mac || 'Unknown';
    
    // Enhanced vendor detection from MAC
    const enhancedVendor = getVendorFromMAC(mac);
    const finalVendor = vendor !== 'Unknown' ? vendor : enhancedVendor;
    
    // Try to identify specific device type using your original working logic
    let deviceType = 'Unknown Device';
    let confidence = 0;
    
    // Check against device signature patterns
    for (const [category, data] of Object.entries(DEVICE_SIGNATURES)) {
        for (const pattern of data.patterns) {
            let matches = 0;
            let totalChecks = 0;
            
            // Check vendor match
            if (pattern.vendor && finalVendor.match(pattern.vendor)) {
                matches += 2; // Vendor match is worth 2 points
            }
            totalChecks += 2;
            
            // Check port matches
            if (pattern.ports) {
                for (const port of pattern.ports) {
                    totalChecks += 1;
                    if (openPorts.includes(port)) {
                        matches += 1;
                    }
                }
            }
            
            const matchConfidence = totalChecks > 0 ? (matches / totalChecks) * 100 : 0;
            
            if (matchConfidence > confidence && matchConfidence > 30) {
                confidence = matchConfidence;
                deviceType = pattern.name;
            }
        }
    }
    
    // Additional hostname-based detection with more patterns
    if (hostname && hostname !== 'Unknown') {
        const lowerHostname = hostname.toLowerCase();
        
        // Simple hostname checks - expanded patterns
        if (lowerHostname.includes('nintendo') && deviceType === 'Unknown Device') {
            deviceType = 'Nintendo Device';
            confidence = 75;
        } else if (lowerHostname.includes('iphone') && deviceType === 'Unknown Device') {
            deviceType = 'iPhone';
            confidence = 80;
        } else if (lowerHostname.includes('ipad') && deviceType === 'Unknown Device') {
            deviceType = 'iPad';
            confidence = 80;
        } else if (lowerHostname.includes('macbook') && deviceType === 'Unknown Device') {
            deviceType = 'MacBook';
            confidence = 80;
        } else if (lowerHostname.includes('android') && deviceType === 'Unknown Device') {
            deviceType = 'Android Device';
            confidence = 75;
        } else if (lowerHostname.includes('windows') && deviceType === 'Unknown Device') {
            deviceType = 'Windows PC';
            confidence = 70;
        } else if (lowerHostname.includes('desktop') && deviceType === 'Unknown Device') {
            deviceType = 'Desktop Computer';
            confidence = 70;
        } else if (lowerHostname.includes('laptop') && deviceType === 'Unknown Device') {
            deviceType = 'Laptop Computer';
            confidence = 70;
        } else if (lowerHostname.includes('raspberry') || lowerHostname.includes('pi') && deviceType === 'Unknown Device') {
            deviceType = 'Raspberry Pi';
            confidence = 85;
        } else if (lowerHostname.includes('esp32') || lowerHostname.includes('esp8266') && deviceType === 'Unknown Device') {
            deviceType = 'ESP32/ESP8266 Device';
            confidence = 90;
        } else if (lowerHostname.includes('ubuntu') && deviceType === 'Unknown Device') {
            deviceType = 'Ubuntu Linux';
            confidence = 75;
        } else if (lowerHostname.includes('debian') && deviceType === 'Unknown Device') {
            deviceType = 'Debian Linux';
            confidence = 75;
        } else if (lowerHostname.includes('router') && deviceType === 'Unknown Device') {
            deviceType = 'Network Router';
            confidence = 80;
        } else if (lowerHostname.includes('switch') && deviceType === 'Unknown Device') {
            deviceType = 'Network Switch';
            confidence = 80;
        } else if (lowerHostname.includes('camera') && deviceType === 'Unknown Device') {
            deviceType = 'IP Camera';
            confidence = 75;
        } else if (lowerHostname.includes('printer') && deviceType === 'Unknown Device') {
            deviceType = 'Network Printer';
            confidence = 80;
        }
    }
    
    // MAC-based vendor guessing if still unknown
    if (deviceType === 'Unknown Device' && finalVendor !== 'Unknown Vendor') {
        const vendorLower = finalVendor.toLowerCase();
        
        if (vendorLower.includes('apple')) {
            if (openPorts.includes(62078)) deviceType = 'iPhone/iPad';
            else if (openPorts.includes(22) && openPorts.includes(548)) deviceType = 'Mac Computer';
            else if (openPorts.includes(3689)) deviceType = 'Apple TV';
            else deviceType = 'Apple Device';
            confidence = 60;
        } else if (vendorLower.includes('samsung')) {
            if (openPorts.includes(8001) || openPorts.includes(8002)) deviceType = 'Samsung Smart TV';
            else deviceType = 'Samsung Device';
            confidence = 55;
        } else if (vendorLower.includes('lg')) {
            if (openPorts.includes(3000) || openPorts.includes(3001)) deviceType = 'LG Smart TV';
            else deviceType = 'LG Device';
            confidence = 55;
        } else if (vendorLower.includes('nintendo')) {
            deviceType = 'Nintendo Gaming Device';
            confidence = 70;
        } else if (vendorLower.includes('brother') || vendorLower.includes('hp') || vendorLower.includes('canon') || vendorLower.includes('epson')) {
            deviceType = 'Network Printer';
            confidence = 65;
        } else if (vendorLower.includes('raspberry')) {
            deviceType = 'Raspberry Pi';
            confidence = 85;
        } else if (vendorLower.includes('intel')) {
            if (openPorts.includes(22)) deviceType = 'Intel-based Computer';
            else deviceType = 'Intel Device';
            confidence = 45;
        } else if (vendorLower.includes('cisco') || vendorLower.includes('netgear') || vendorLower.includes('linksys') || vendorLower.includes('asus') || vendorLower.includes('d-link') || vendorLower.includes('tp-link')) {
            deviceType = 'Network Equipment';
            confidence = 70;
        } else if (vendorLower.includes('microsoft')) {
            if (openPorts.includes(3389)) deviceType = 'Windows Computer';
            else deviceType = 'Microsoft Device';
            confidence = 60;
        } else if (vendorLower.includes('sony')) {
            if (openPorts.includes(80) && openPorts.includes(443)) deviceType = 'Sony Smart Device';
            else deviceType = 'Sony Device';
            confidence = 55;
        } else if (vendorLower.includes('google') || vendorLower.includes('nest')) {
            if (openPorts.includes(8008) || openPorts.includes(8009)) deviceType = 'Google Chromecast/Nest';
            else deviceType = 'Google Device';
            confidence = 60;
        } else if (vendorLower.includes('amazon')) {
            if (openPorts.includes(8080)) deviceType = 'Amazon Fire TV';
            else deviceType = 'Amazon Device';
            confidence = 60;
        } else if (vendorLower.includes('roku')) {
            deviceType = 'Roku Streaming Device';
            confidence = 80;
        } else if (vendorLower.includes('hikvision') || vendorLower.includes('dahua')) {
            deviceType = 'Security Camera';
            confidence = 85;
        } else if (vendorLower.includes('mediatek') || vendorLower.includes('realtek') || vendorLower.includes('broadcom') || vendorLower.includes('qualcomm')) {
            deviceType = 'IoT Device (Chipset: ' + finalVendor + ')';
            confidence = 50;
        } else if (vendorLower.includes('virtual') || vendorLower.includes('qemu') || vendorLower.includes('vmware')) {
            deviceType = 'Virtual Machine';
            confidence = 90;
        } else if (vendorLower.includes('shenzhen') || vendorLower.includes('shiningworth')) {
            deviceType = 'Smart Home Device (Shenzhen Mfg)';
            confidence = 70;
        } else if (vendorLower.includes('texas instruments')) {
            deviceType = 'IoT Device (TI Chipset)';
            confidence = 65;
        } else if (vendorLower.includes('arcadyan')) {
            deviceType = 'Router/Gateway Device';
            confidence = 80;
        } else if (vendorLower.includes('chongqing') || vendorLower.includes('fugui')) {
            deviceType = 'Smart Device (Chinese Mfg)';
            confidence = 65;
        } else if (vendorLower.includes('sichuan') || vendorLower.includes('ai-link')) {
            deviceType = 'IoT Smart Device';
            confidence = 70;
        } else if (vendorLower.includes('silex')) {
            deviceType = 'Wireless Module Device';
            confidence = 75;
        } else if (vendorLower.includes('espressif')) {
            deviceType = 'ESP32/ESP8266 IoT Device';
            confidence = 85;
        }
    }
    
    // Special handling for devices with no open ports (common in IoT devices)
    if (openPorts.length === 0 && deviceType === 'Unknown Device' && finalVendor !== 'Unknown Vendor') {
        const vendorLower = finalVendor.toLowerCase();
        
        // Many IoT devices don't expose ports but can still be identified by vendor
        if (vendorLower.includes('shenzhen') || vendorLower.includes('shiningworth')) {
            deviceType = 'Smart Home Device (Secured)';
            confidence = 65;
        } else if (vendorLower.includes('texas instruments')) {
            deviceType = 'IoT Sensor Device';
            confidence = 60;
        } else if (vendorLower.includes('arcadyan')) {
            deviceType = 'Network Gateway (Secured)';
            confidence = 70;
        } else if (vendorLower.includes('chongqing') || vendorLower.includes('fugui')) {
            deviceType = 'IoT Device (Secured)';
            confidence = 60;
        } else if (vendorLower.includes('sichuan') || vendorLower.includes('ai-link')) {
            deviceType = 'Smart IoT Device (Secured)';
            confidence = 65;
        } else if (vendorLower.includes('silex')) {
            deviceType = 'Wireless Module (Secured)';
            confidence = 70;
        } else if (vendorLower.includes('espressif')) {
            deviceType = 'ESP32/ESP8266 Device (Secured)';
            confidence = 80;
        } else if (vendorLower.includes('mediatek') || vendorLower.includes('realtek') || vendorLower.includes('broadcom')) {
            deviceType = 'IoT Device (Secured Chipset)';
            confidence = 55;
        } else if (vendorLower.includes('apple')) {
            deviceType = 'Apple Device (Secured)';
            confidence = 55;
        } else if (vendorLower.includes('samsung')) {
            deviceType = 'Samsung Device (Secured)';
            confidence = 55;
        } else if (vendorLower.includes('amazon')) {
            deviceType = 'Amazon Device (Secured)';
            confidence = 60;
        } else if (vendorLower.includes('google')) {
            deviceType = 'Google Device (Secured)';
            confidence = 60;
        } else {
            // Generic IoT device for any known vendor with no ports
            deviceType = 'IoT Device (Secured/Sleeping)';
            confidence = 45;
        }
    }
    
    // Port-based guessing for completely unknown devices
    if (deviceType === 'Unknown Device' && openPorts.length > 0) {
        if (openPorts.includes(631) || openPorts.includes(9100)) {
            deviceType = 'Network Printer';
            confidence = 60;
        } else if (openPorts.includes(8008) || openPorts.includes(8009)) {
            deviceType = 'Chromecast/Media Device';
            confidence = 55;
        } else if (openPorts.includes(22) && openPorts.length === 1) {
            deviceType = 'SSH Server/Linux Device';
            confidence = 40;
        } else if (openPorts.includes(80) && openPorts.includes(443) && openPorts.length === 2) {
            deviceType = 'Web Server/IoT Device';
            confidence = 35;
        } else if (openPorts.includes(1900)) {
            deviceType = 'UPnP Device';
            confidence = 50;
        } else if (openPorts.includes(554)) {
            deviceType = 'Security Camera/RTSP Device';
            confidence = 60;
        } else if (openPorts.includes(8080)) {
            deviceType = 'Web Service/IoT Device';
            confidence = 35;
        } else if (openPorts.includes(3389)) {
            deviceType = 'Windows Computer (RDP)';
            confidence = 70;
        } else if (openPorts.includes(5900)) {
            deviceType = 'VNC Server';
            confidence = 65;
        } else if (openPorts.includes(8001) || openPorts.includes(8002)) {
            deviceType = 'Smart TV';
            confidence = 50;
        } else if (openPorts.includes(3000)) {
            deviceType = 'Smart TV (LG webOS)';
            confidence = 60;
        }
    }
    
    // Detect operating system
    let operatingSystem = 'Unknown OS';
    let osConfidence = 0;
    
    for (const [osName, osPattern] of Object.entries(OS_PATTERNS)) {
        let osMatches = 0;
        for (const port of osPattern.ports) {
            if (openPorts.includes(port)) {
                osMatches++;
            }
        }
        
        const osMatchConfidence = osPattern.ports.length > 0 ? 
            (osMatches / osPattern.ports.length) * 100 : 0;
            
        if (osMatchConfidence > osConfidence) {
            osConfidence = osMatchConfidence;
            operatingSystem = osPattern.name;
        }
    }
    
    // Identify services
    const services = openPorts.map(port => {
        return SERVICE_PATTERNS[port] || 'Port ' + port;
    });
    
    return {
        ip: device.ip,
        hostname: hostname,
        mac: mac,
        vendor: finalVendor,
        deviceType: deviceType,
        operatingSystem: operatingSystem,
        confidence: Math.round(confidence),
        openPorts: openPorts,
        services: services,
        state: device.state || 'up',
        lastSeen: new Date().toISOString()
    };
}

// Test basic nmap functionality
function testNmap() {
    return new Promise((resolve, reject) => {
        console.log('🧪 Testing nmap installation...');
        
        const quickscan = new nmap.QuickScan('127.0.0.1');
        
        quickscan.on('complete', function(data) {
            console.log('✅ Nmap test successful!');
            resolve(true);
        });
        
        quickscan.on('error', function(error) {
            console.error('❌ Nmap test failed:', error.message);
            reject(error);
        });
        
        quickscan.startScan();
    });
}

// Enhanced network scanning with better compatibility
function scanNetwork(subnet) {
    return new Promise((resolve, reject) => {
        console.log('🔍 Starting enhanced network scan of: ' + subnet);
        
        // First try enhanced scan with QuickScan + port detection
        enhancedQuickScan(subnet)
            .then(devices => {
                console.log('✅ Enhanced scan completed! Found ' + devices.length + ' devices');
                resolve(devices);
            })
            .catch(error => {
                console.error('❌ Enhanced scan failed, trying fallback:', error.message);
                // Fallback to basic scan
                fallbackBasicScan(subnet, resolve, reject);
            });
    });
}

// Enhanced QuickScan with port detection
function enhancedQuickScan(subnet) {
    return new Promise((resolve, reject) => {
        console.log('🔍 Running enhanced QuickScan...');
        
        const quickscan = new nmap.QuickScan(subnet);
        
        quickscan.on('complete', function(data) {
            console.log('📡 Basic scan found ' + data.length + ' devices, enhancing detection...');
            
            // Enhance each device with additional port scanning
            const enhancementPromises = data.map(device => enhanceDeviceInfo(device));
            
            Promise.all(enhancementPromises)
                .then(enhancedDevices => {
                    const finalDevices = enhancedDevices.map((device, index) => {
                        console.log('📱 Enhanced device ' + (index + 1) + ': ' + device.ip);
                        
                        const enhancedDevice = identifyDevice(device);
                        
                        console.log('   └─ Identified as: ' + enhancedDevice.deviceType + ' (' + enhancedDevice.confidence + '% confidence)');
                        console.log('   └─ Vendor: ' + enhancedDevice.vendor);
                        
                        return enhancedDevice;
                    });
                    
                    resolve(finalDevices);
                })
                .catch(error => {
                    console.error('❌ Device enhancement failed:', error);
                    // Still return basic devices with enhancement
                    const basicDevices = data.map(device => identifyDevice(device));
                    resolve(basicDevices);
                });
        });
        
        quickscan.on('error', function(error) {
            console.error('❌ QuickScan error:', error.message);
            reject(error);
        });
        
        quickscan.startScan();
    });
}

// Enhance individual device info with port scanning
function enhanceDeviceInfo(device) {
    return new Promise((resolve) => {
        // Try to get more port information for the device
        const portScan = new nmap.QuickScan(device.ip);
        
        const timeout = setTimeout(() => {
            console.log('⏰ Port scan timeout for ' + device.ip + ', using basic info');
            resolve(device);
        }, 10000); // 10 second timeout per device
        
        portScan.on('complete', function(portData) {
            clearTimeout(timeout);
            
            if (portData && portData.length > 0) {
                const enhancedDevice = Object.assign({}, device, portData[0]);
                console.log('🔍 Enhanced ports for ' + device.ip + ': ' + (enhancedDevice.openPorts || 'none detected'));
                resolve(enhancedDevice);
            } else {
                resolve(device);
            }
        });
        
        portScan.on('error', function(error) {
            clearTimeout(timeout);
            console.log('⚠ Port scan failed for ' + device.ip + ', using basic info');
            resolve(device);
        });
        
        portScan.startScan();
    });
}

// Fallback basic scan if enhanced scan fails
function fallbackBasicScan(subnet, resolve, reject) {
    console.log('🔄 Running fallback basic scan...');
    
    const quickscan = new nmap.QuickScan(subnet);
    
    quickscan.on('complete', function(data) {
        console.log('✅ Fallback scan completed! Found ' + data.length + ' devices');
        
        const devices = data.map((device, index) => {
            console.log('📱 Device ' + (index + 1) + ': ' + device.ip + ' - ' + (device.hostname || 'Unknown'));
            
            const enhancedDevice = identifyDevice(device);
            
            return enhancedDevice;
        });
        
        resolve(devices);
    });
    
    quickscan.on('error', function(error) {
        console.error('❌ Fallback scan also failed:', error.message);
        reject(error);
    });
    
    quickscan.startScan();
}

module.exports = {
    getNetworkInfo,
    testNmap,
    scanNetwork
};