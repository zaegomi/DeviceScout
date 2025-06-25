const nmap = require('node-nmap');
const os = require('os');

// Vulnerability Assessment Functions
const VULNERABILITY_CHECKS = {
    // Dangerous open ports
    criticalPorts: {
        21: { risk: 'HIGH', issue: 'FTP server - often unencrypted', cve: 'CVE-2019-12815' },
        23: { risk: 'CRITICAL', issue: 'Telnet - unencrypted remote access', cve: 'CVE-2020-15778' },
        135: { risk: 'HIGH', issue: 'Windows RPC - vulnerable to attacks', cve: 'CVE-2022-26937' },
        139: { risk: 'MEDIUM', issue: 'NetBIOS - information disclosure', cve: 'CVE-2021-31166' },
        445: { risk: 'HIGH', issue: 'SMB - vulnerable to ransomware', cve: 'CVE-2020-0796' },
        1433: { risk: 'HIGH', issue: 'SQL Server - data exposure risk', cve: 'CVE-2021-1636' },
        3306: { risk: 'HIGH', issue: 'MySQL database exposed', cve: 'CVE-2021-2471' },
        3389: { risk: 'MEDIUM', issue: 'RDP - brute force target', cve: 'CVE-2019-0708' },
        5432: { risk: 'HIGH', issue: 'PostgreSQL database exposed', cve: 'CVE-2021-23222' },
        5900: { risk: 'MEDIUM', issue: 'VNC - weak authentication', cve: 'CVE-2020-14002' }
    }
};

const DEVICE_VULNERABILITIES = {
    'Brother Printer': [
        { risk: 'MEDIUM', issue: 'Default SNMP community string', cve: 'CVE-2021-3114' },
        { risk: 'LOW', issue: 'Web interface information disclosure', cve: 'CVE-2020-5655' }
    ],
    'HP Printer': [
        { risk: 'HIGH', issue: 'Buffer overflow in web interface', cve: 'CVE-2021-39237' },
        { risk: 'MEDIUM', issue: 'Authentication bypass', cve: 'CVE-2021-39238' }
    ],
    'Hikvision Security Camera': [
        { risk: 'CRITICAL', issue: 'Command injection vulnerability', cve: 'CVE-2021-36260' },
        { risk: 'HIGH', issue: 'Authentication bypass', cve: 'CVE-2020-25078' }
    ],
    'NETGEAR Router': [
        { risk: 'CRITICAL', issue: 'Pre-auth RCE vulnerability', cve: 'CVE-2021-34991' },
        { risk: 'HIGH', issue: 'Password disclosure', cve: 'CVE-2021-34992' }
    ],
    'Network Equipment': [
        { risk: 'HIGH', issue: 'Default credentials may be in use', cve: 'N/A' },
        { risk: 'MEDIUM', issue: 'Firmware may be outdated', cve: 'N/A' }
    ]
};

// Enhanced device fingerprinting database
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

// Enhanced MAC address vendor database
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
    
    // IoT Device Manufacturers
    "C4:4E:AC": "Shenzhen Shiningworth Technology",
    "F4:B8:5E": "Texas Instruments",
    "EC:6C:9A": "Arcadyan",
    "C0:B5:D7": "Chongqing Fugui Electronics", 
    "C0:E7:BF": "Sichuan AI-Link Technology",
    "00:80:92": "Silex Technology",
    "B8:27:EB": "Raspberry Pi Trading",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "52:54:00": "QEMU Virtual Network",
    "08:00:27": "Oracle VirtualBox",
    "00:0C:29": "VMware Inc",
    "00:50:56": "VMware Inc"
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

// Security Assessment Function
function performSecurityAssessment(devices) {
    console.log('🔒 Starting security assessment...');
    
    let totalScore = 0;
    let allVulnerabilities = [];
    let deviceAssessments = [];
    
    devices.forEach((device, index) => {
        console.log('🔍 Security analysis for device ' + (index + 1) + ': ' + device.ip);
        
        let deviceScore = 100;
        let deviceVulns = [];
        
        // Check for dangerous ports
        device.openPorts.forEach(port => {
            if (VULNERABILITY_CHECKS.criticalPorts[port]) {
                const vuln = VULNERABILITY_CHECKS.criticalPorts[port];
                deviceVulns.push({
                    device: device.ip,
                    deviceType: device.deviceType,
                    port: port,
                    risk: vuln.risk,
                    issue: vuln.issue,
                    cve: vuln.cve,
                    type: 'PORT_VULNERABILITY'
                });
                
                // Deduct points based on risk
                switch(vuln.risk) {
                    case 'CRITICAL': deviceScore -= 25; break;
                    case 'HIGH': deviceScore -= 15; break;
                    case 'MEDIUM': deviceScore -= 8; break;
                    case 'LOW': deviceScore -= 3; break;
                }
            }
        });
        
        // Check for device-specific vulnerabilities
        if (DEVICE_VULNERABILITIES[device.deviceType]) {
            DEVICE_VULNERABILITIES[device.deviceType].forEach(vuln => {
                deviceVulns.push({
                    device: device.ip,
                    deviceType: device.deviceType,
                    risk: vuln.risk,
                    issue: vuln.issue,
                    cve: vuln.cve,
                    type: 'DEVICE_VULNERABILITY'
                });
                
                switch(vuln.risk) {
                    case 'CRITICAL': deviceScore -= 20; break;
                    case 'HIGH': deviceScore -= 12; break;
                    case 'MEDIUM': deviceScore -= 6; break;
                    case 'LOW': deviceScore -= 2; break;
                }
            });
        }
        
        // Security bonuses and penalties
        if (device.openPorts.length === 0) {
            deviceScore += 5; // Bonus for no open ports
        } else if (device.openPorts.length > 10) {
            deviceScore -= 10; // Penalty for too many ports
            deviceVulns.push({
                device: device.ip,
                deviceType: device.deviceType,
                risk: 'MEDIUM',
                issue: 'Too many open ports (' + device.openPorts.length + ')',
                description: 'Large attack surface increases vulnerability',
                type: 'CONFIGURATION'
            });
        }
        
        // Unknown device penalty
        if (device.deviceType === 'Unknown Device' || device.confidence < 30) {
            deviceScore -= 8;
            deviceVulns.push({
                device: device.ip,
                deviceType: device.deviceType,
                risk: 'MEDIUM',
                issue: 'Unidentified device on network',
                description: 'Unknown devices may pose security risks',
                type: 'IDENTIFICATION'
            });
        }
        
        // Apply security criteria
        if (device.openPorts.includes(443)) deviceScore += 3; // HTTPS bonus
        if (device.openPorts.includes(22)) deviceScore += 2; // SSH bonus
        if (device.openPorts.includes(23)) deviceScore -= 15; // Telnet penalty
        if (device.openPorts.includes(21)) deviceScore -= 10; // FTP penalty
        
        deviceScore = Math.max(0, Math.min(100, deviceScore));
        
        const deviceAssessment = {
            device: device.ip,
            deviceType: device.deviceType,
            score: deviceScore,
            vulnerabilities: deviceVulns,
            riskLevel: deviceScore >= 80 ? 'LOW' : deviceScore >= 60 ? 'MEDIUM' : deviceScore >= 40 ? 'HIGH' : 'CRITICAL'
        };
        
        deviceAssessments.push(deviceAssessment);
        allVulnerabilities = allVulnerabilities.concat(deviceVulns);
        totalScore += deviceScore;
        
        console.log('   └─ Device Score: ' + deviceScore + '/100');
        console.log('   └─ Vulnerabilities: ' + deviceVulns.length);
    });
    
    // Calculate network-wide score
    const averageScore = devices.length > 0 ? Math.round(totalScore / devices.length) : 0;
    
    // Apply network penalties
    let networkPenalties = 0;
    const criticalVulns = allVulnerabilities.filter(v => v.risk === 'CRITICAL');
    const highVulns = allVulnerabilities.filter(v => v.risk === 'HIGH');
    
    networkPenalties += criticalVulns.length * 5;
    networkPenalties += highVulns.length * 2;
    
    const finalScore = Math.max(0, averageScore - networkPenalties);
    
    // Generate recommendations
    const recommendations = generateRecommendations(allVulnerabilities, devices);
    
    console.log('🎯 Final Network Security Score: ' + finalScore + '/100');
    
    return {
        overallScore: finalScore,
        averageDeviceScore: averageScore,
        totalVulnerabilities: allVulnerabilities.length,
        criticalVulnerabilities: criticalVulns.length,
        highVulnerabilities: highVulns.length,
        vulnerabilities: allVulnerabilities,
        recommendations: recommendations,
        deviceAssessments: deviceAssessments,
        networkPenalties: networkPenalties
    };
}

function generateRecommendations(vulnerabilities, devices) {
    let recommendations = [];
    
    // Critical vulnerabilities
    const criticalVulns = vulnerabilities.filter(v => v.risk === 'CRITICAL');
    criticalVulns.forEach(vuln => {
        recommendations.push({
            priority: 'CRITICAL',
            action: 'Immediately address ' + vuln.issue + ' on ' + vuln.deviceType + ' (' + vuln.device + ')',
            reason: vuln.issue,
            cve: vuln.cve
        });
    });
    
    // Telnet detection
    const telnetDevices = vulnerabilities.filter(v => v.port === 23);
    if (telnetDevices.length > 0) {
        recommendations.push({
            priority: 'HIGH',
            action: 'Disable Telnet and use SSH instead on ' + telnetDevices.length + ' device(s)',
            reason: 'Telnet sends passwords in plain text'
        });
    }
    
    // FTP detection  
    const ftpDevices = vulnerabilities.filter(v => v.port === 21);
    if (ftpDevices.length > 0) {
        recommendations.push({
            priority: 'MEDIUM',
            action: 'Replace FTP with SFTP on ' + ftpDevices.length + ' device(s)',
            reason: 'FTP is unencrypted and vulnerable'
        });
    }
    
    // Database exposure
    const dbPorts = [1433, 3306, 5432];
    const exposedDbs = vulnerabilities.filter(v => dbPorts.includes(v.port));
    if (exposedDbs.length > 0) {
        recommendations.push({
            priority: 'HIGH',
            action: 'Secure or firewall exposed databases',
            reason: 'Database servers should not be directly accessible'
        });
    }
    
    // Unknown devices
    const unknownDevices = devices.filter(d => d.deviceType === 'Unknown Device');
    if (unknownDevices.length > 0) {
        recommendations.push({
            priority: 'MEDIUM',
            action: 'Identify and inventory ' + unknownDevices.length + ' unknown device(s)',
            reason: 'Unidentified devices pose potential security risks'
        });
    }
    
    // High-risk devices
    const highRiskDevices = devices.filter(d => d.openPorts && d.openPorts.length > 5);
    if (highRiskDevices.length > 0) {
        recommendations.push({
            priority: 'LOW',
            action: 'Review open ports on ' + highRiskDevices.length + ' device(s)',
            reason: 'Reduce attack surface by closing unnecessary ports'
        });
    }
    
    return recommendations.slice(0, 6); // Top 6 recommendations
}

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

// Enhanced device identification
function identifyDevice(device) {
    const vendor = device.vendor || 'Unknown';
    const hostname = device.hostname || 'Unknown';
    const openPorts = device.openPorts || [];
    const mac = device.mac || 'Unknown';
    
    // Enhanced vendor detection from MAC
    const enhancedVendor = getVendorFromMAC(mac);
    const finalVendor = vendor !== 'Unknown' ? vendor : enhancedVendor;
    
    // Try to identify specific device type using signature patterns
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
    
    // Enhanced hostname-based detection
    if (hostname && hostname !== 'Unknown') {
        const lowerHostname = hostname.toLowerCase();
        
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
        }
    }
    
    // MAC-based vendor guessing if still unknown
    if (deviceType === 'Unknown Device' && finalVendor !== 'Unknown Vendor') {
        const vendorLower = finalVendor.toLowerCase();
        
        if (vendorLower.includes('shenzhen') || vendorLower.includes('shiningworth')) {
            deviceType = 'Smart Home Device (Secured)';
            confidence = 65;
        } else if (vendorLower.includes('texas instruments')) {
            deviceType = 'IoT Sensor Device';
            confidence = 60;
        } else if (vendorLower.includes('arcadyan')) {
            deviceType = 'Network Gateway (Secured)';
            confidence = 70;
        } else if (vendorLower.includes('apple')) {
            if (openPorts.includes(62078)) deviceType = 'iPhone/iPad';
            else if (openPorts.includes(22) && openPorts.includes(548)) deviceType = 'Mac Computer';
            else if (openPorts.includes(3689)) deviceType = 'Apple TV';
            else deviceType = 'Apple Device';
            confidence = 60;
        } else if (vendorLower.includes('brother') || vendorLower.includes('hp') || vendorLower.includes('canon') || vendorLower.includes('epson')) {
            deviceType = 'Network Printer';
            confidence = 65;
        } else if (vendorLower.includes('raspberry')) {
            deviceType = 'Raspberry Pi';
            confidence = 85;
        } else if (vendorLower.includes('nintendo')) {
            deviceType = 'Nintendo Gaming Device';
            confidence = 70;
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

// Main scan network function
function scanNetwork(subnet) {
    return new Promise((resolve, reject) => {
        console.log('🔍 Starting enhanced network scan of: ' + subnet);
        
        // First try enhanced scan with QuickScan + port detection
        enhancedQuickScan(subnet)
            .then(result => {
                console.log('✅ Enhanced scan completed! Found ' + result.devices.length + ' devices');
                resolve(result);
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
                    
                    // Perform comprehensive security assessment
                    console.log('🔒 Running security vulnerability assessment...');
                    const securityAssessment = performSecurityAssessment(finalDevices);
                    
                    // Return properly structured result
                    const result = {
                        devices: finalDevices,
                        securityAssessment: securityAssessment
                    };
                    
                    resolve(result);
                })
                .catch(error => {
                    console.error('❌ Device enhancement failed:', error);
                    // Still return basic devices with enhancement
                    const basicDevices = data.map(device => identifyDevice(device));
                    
                    // Perform security assessment on basic devices too
                    const securityAssessment = performSecurityAssessment(basicDevices);
                    
                    resolve({
                        devices: basicDevices,
                        securityAssessment: securityAssessment
                    });
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
        
        // Perform security assessment
        const securityAssessment = performSecurityAssessment(devices);
        
        resolve({
            devices: devices,
            securityAssessment: securityAssessment
        });
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