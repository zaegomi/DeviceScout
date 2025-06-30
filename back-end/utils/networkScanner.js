const nmap = require('node-nmap');
const os = require('os');

// Common default credentials database
const DEFAULT_CREDENTIALS = {
    'admin': ['admin', 'password', '123456', '', 'default'],
    'root': ['root', 'admin', 'password', 'toor', ''],
    'user': ['user', 'password', '123456'],
    'guest': ['guest', '', 'password'],
    'support': ['support', 'password'],
    'pi': ['raspberry', 'pi'],
    'ubnt': ['ubnt'],
    'admin': ['epicrouter', 'motorola', 'password1']
};

// Known vulnerable ports and services (reduced list for faster scanning)
const VULNERABLE_PORTS = {
    21: { service: 'FTP', risk: 'high', description: 'FTP servers often have weak authentication' },
    22: { service: 'SSH', risk: 'medium', description: 'SSH with weak passwords is vulnerable to brute force' },
    23: { service: 'Telnet', risk: 'critical', description: 'Unencrypted remote access protocol' },
    80: { service: 'HTTP', risk: 'medium', description: 'Unencrypted web interface' },
    443: { service: 'HTTPS', risk: 'low', description: 'Encrypted web interface' },
    3389: { service: 'RDP', risk: 'high', description: 'Remote desktop with potential weak authentication' },
    5900: { service: 'VNC', risk: 'high', description: 'Remote desktop often with weak passwords' },
    8080: { service: 'HTTP-Alt', risk: 'medium', description: 'Alternative web port, often admin interfaces' },
    9100: { service: 'Printer', risk: 'medium', description: 'Network printer with potential default access' }
};

// Device manufacturer vulnerability patterns
const DEVICE_VULNERABILITIES = {
    'Brother': {
        type: 'printer',
        commonIssues: ['Default admin password', 'Unencrypted web interface', 'Firmware updates needed'],
        defaultCreds: [['admin', 'access'], ['admin', '']]
    },
    'HP': {
        type: 'printer',
        commonIssues: ['Default admin password', 'Open SNMP', 'Firmware vulnerabilities'],
        defaultCreds: [['admin', 'admin'], ['admin', '']]
    },
    'Canon': {
        type: 'printer',
        commonIssues: ['Default admin password', 'Unencrypted protocols'],
        defaultCreds: [['ADMIN', 'canon'], ['admin', '']]
    },
    'D-Link': {
        type: 'router',
        commonIssues: ['Default admin credentials', 'Weak WPS', 'Firmware vulnerabilities'],
        defaultCreds: [['admin', 'admin'], ['admin', '']]
    },
    'Netgear': {
        type: 'router',
        commonIssues: ['Default credentials', 'Remote management enabled', 'UPnP vulnerabilities'],
        defaultCreds: [['admin', 'password'], ['admin', 'admin']]
    },
    'Linksys': {
        type: 'router',
        commonIssues: ['Default credentials', 'WPS vulnerabilities', 'Remote access'],
        defaultCreds: [['admin', 'admin'], ['admin', '']]
    },
    'Hikvision': {
        type: 'camera',
        commonIssues: ['Default passwords', 'Unencrypted streams', 'Backdoor vulnerabilities'],
        defaultCreds: [['admin', '12345'], ['admin', 'admin']]
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
                        const subnetBase = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
                        
                        networkInfo = {
                            interface: name,
                            ip: ip,
                            netmask: netmask,
                            subnet: subnetBase
                        };
                        
                        console.log(`✅ Found active interface: ${name} (${ip})`);
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

// Fast port scan on specific device (only common ports)
function fastPortScan(host) {
    return new Promise((resolve, reject) => {
        console.log(`🔍 Fast port scan on ${host}...`);
        
        // Only scan most common ports for speed
        const commonPorts = '21,22,23,53,80,110,143,443,993,995,3389,5900,8080,9100';
        const nmapScan = new nmap.NmapScan(host, `-p ${commonPorts} --open -T4`);
        
        // Set timeout to prevent hanging
        const timeout = setTimeout(() => {
            console.log(`⏰ Port scan timeout for ${host}`);
            resolve({ host: host, openPorts: [], timeout: true });
        }, 10000); // 10 second timeout
        
        nmapScan.on('complete', function(data) {
            clearTimeout(timeout);
            if (data && data.length > 0) {
                resolve(data[0]);
            } else {
                resolve({ host: host, openPorts: [] });
            }
        });
        
        nmapScan.on('error', function(error) {
            clearTimeout(timeout);
            console.error(`❌ Port scan failed for ${host}:`, error.message);
            resolve({ host: host, openPorts: [], error: error.message });
        });
        
        nmapScan.startScan();
    });
}

// Analyze security vulnerabilities for a device (simplified)
function analyzeDeviceSecurity(device) {
    const vulnerabilities = [];
    const recommendations = [];
    let riskScore = 0;

    // Check for known vendor vulnerabilities
    if (device.vendor && DEVICE_VULNERABILITIES[device.vendor]) {
        const vendorVulns = DEVICE_VULNERABILITIES[device.vendor];
        vulnerabilities.push(...vendorVulns.commonIssues);
        riskScore += 30;
        
        recommendations.push(`Update ${device.vendor} ${vendorVulns.type} firmware to latest version`);
        recommendations.push(`Change default credentials for ${device.vendor} device`);
    }

    // Analyze open ports (simplified)
    if (device.openPorts && device.openPorts.length > 0) {
        device.openPorts.forEach(portInfo => {
            const port = portInfo.port;
            
            if (VULNERABLE_PORTS[port]) {
                const vulnInfo = VULNERABLE_PORTS[port];
                vulnerabilities.push(`${vulnInfo.service} (${port}) - ${vulnInfo.description}`);
                
                switch (vulnInfo.risk) {
                    case 'critical':
                        riskScore += 40;
                        break;
                    case 'high':
                        riskScore += 25;
                        break;
                    case 'medium':
                        riskScore += 15;
                        break;
                    case 'low':
                        riskScore += 5;
                        break;
                }
                
                // Add specific recommendations
                if (port === 23) {
                    recommendations.push('Disable Telnet and use SSH instead');
                } else if (port === 21) {
                    recommendations.push('Secure FTP server or use SFTP/FTPS');
                } else if (port === 3389) {
                    recommendations.push('Enable Network Level Authentication for RDP');
                } else if ([80, 8080].includes(port)) {
                    recommendations.push('Enable HTTPS and disable HTTP if possible');
                }
            }
        });
    }

    // Check for too many open ports
    if (device.openPorts && device.openPorts.length > 5) {
        vulnerabilities.push('Multiple open ports detected');
        riskScore += 15;
        recommendations.push('Review and close unnecessary network services');
    }

    // Check for unknown devices
    if (!device.vendor || device.vendor === 'Unknown') {
        vulnerabilities.push('Unidentified device on network');
        riskScore += 15;
        recommendations.push('Investigate unknown device and verify it belongs on network');
    }

    // Check for devices with no hostname
    if (!device.hostname || device.hostname === 'Unknown') {
        vulnerabilities.push('Device lacks proper hostname configuration');
        riskScore += 10;
        recommendations.push('Configure proper hostname for device identification');
    }

    return {
        vulnerabilities,
        recommendations,
        riskScore: Math.min(riskScore, 100),
        securityLevel: getRiskLevel(riskScore)
    };
}

// Get risk level based on score
function getRiskLevel(score) {
    if (score >= 75) return 'Critical';
    if (score >= 50) return 'High';
    if (score >= 25) return 'Medium';
    return 'Low';
}

// Calculate overall network security score
function calculateNetworkSecurity(devices) {
    let totalRisk = 0;
    let highRiskDevices = 0;
    let criticalVulnerabilities = 0;
    const networkRecommendations = [];

    devices.forEach(device => {
        if (device.security) {
            totalRisk += device.security.riskScore;
            
            if (device.security.riskScore >= 50) {
                highRiskDevices++;
            }
            
            if (device.security.securityLevel === 'Critical') {
                criticalVulnerabilities++;
            }
        }
    });

    const averageRisk = devices.length > 0 ? totalRisk / devices.length : 0;
    const networkScore = Math.max(0, 100 - averageRisk);

    // Network-level recommendations
    if (highRiskDevices > 0) {
        networkRecommendations.push(`${highRiskDevices} device(s) require immediate security attention`);
    }
    
    if (criticalVulnerabilities > 0) {
        networkRecommendations.push(`${criticalVulnerabilities} device(s) have critical security vulnerabilities`);
    }
    
    if (devices.length > 20) {
        networkRecommendations.push('Large number of devices detected - consider network segmentation');
    }

    return {
        score: Math.round(networkScore),
        level: getRiskLevel(100 - networkScore),
        highRiskDevices,
        criticalVulnerabilities,
        totalDevices: devices.length,
        recommendations: networkRecommendations
    };
}

// Optimized network scan with faster security assessment
function scanNetworkWithSecurity(subnet) {
    return new Promise(async (resolve, reject) => {
        try {
            console.log(`🔍 Starting FAST security scan of: ${subnet}`);
            
            // First, do a quick discovery scan
            const quickscan = new nmap.QuickScan(subnet);
            
            quickscan.on('complete', async function(discoveredDevices) {
                console.log(`✅ Discovery completed! Found ${discoveredDevices.length} devices`);
                
                const enhancedDevices = [];
                
                // Process devices with limited port scanning for speed
                for (let i = 0; i < discoveredDevices.length; i++) {
                    const device = discoveredDevices[i];
                    console.log(`🔍 Analyzing device ${i + 1}/${discoveredDevices.length}: ${device.ip}`);
                    
                    try {
                        // Fast port scan (only if device looks interesting)
                        let portScanData = { openPorts: [] };
                        
                        // Only do detailed scan on devices that might have interesting services
                        if (device.vendor && device.vendor !== 'Unknown') {
                            portScanData = await fastPortScan(device.ip);
                        }
                        
                        // Merge data
                        const enhancedDevice = {
                            ip: device.ip,
                            hostname: device.hostname || portScanData.hostname || 'Unknown',
                            mac: device.mac || portScanData.mac || 'Unknown',
                            vendor: device.vendor || portScanData.vendor || 'Unknown',
                            state: device.state || 'up',
                            openPorts: portScanData.openPorts || [],
                            osNmap: device.osNmap || portScanData.osNmap || 'Unknown',
                            lastSeen: new Date().toISOString()
                        };
                        
                        // Perform security analysis
                        enhancedDevice.security = analyzeDeviceSecurity(enhancedDevice);
                        
                        enhancedDevices.push(enhancedDevice);
                        
                    } catch (error) {
                        console.error(`❌ Error analyzing ${device.ip}:`, error.message);
                        
                        // Add device with basic info even if scan fails
                        const basicDevice = {
                            ip: device.ip,
                            hostname: device.hostname || 'Unknown',
                            mac: device.mac || 'Unknown',
                            vendor: device.vendor || 'Unknown',
                            state: device.state || 'up',
                            openPorts: [],
                            osNmap: device.osNmap || 'Unknown',
                            lastSeen: new Date().toISOString(),
                            security: {
                                vulnerabilities: ['Limited scan - basic assessment only'],
                                recommendations: ['Run detailed scan for complete analysis'],
                                riskScore: 20,
                                securityLevel: 'Medium'
                            }
                        };
                        
                        enhancedDevices.push(basicDevice);
                    }
                }
                
                // Calculate overall network security
                const networkSecurity = calculateNetworkSecurity(enhancedDevices);
                
                console.log(`✅ FAST security scan completed!`);
                console.log(`📊 Network Security Score: ${networkSecurity.score}/100 (${networkSecurity.level})`);
                console.log(`⚠️  High Risk Devices: ${networkSecurity.highRiskDevices}`);
                console.log(`🚨 Critical Vulnerabilities: ${networkSecurity.criticalVulnerabilities}`);
                
                resolve({
                    devices: enhancedDevices,
                    networkSecurity: networkSecurity
                });
                
            });
            
            quickscan.on('error', function(error) {
                console.error('❌ Network scan error:', error.message);
                reject(error);
            });
            
            quickscan.startScan();
            
        } catch (error) {
            console.error('❌ Fast scan failed:', error.message);
            reject(error);
        }
    });
}

module.exports = {
    getNetworkInfo,
    testNmap,
    scanNetwork: scanNetworkWithSecurity
};