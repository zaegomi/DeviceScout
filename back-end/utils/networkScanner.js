const nmap = require('node-nmap');
const os = require('os');
const https = require('https');
const http = require('http');
const net = require('net');

// Enhanced default credentials database with more entries
const DEFAULT_CREDENTIALS = {
    // Router/Network Equipment
    'admin': ['admin', 'password', '123456', '', 'default', '1234', 'admin123'],
    'root': ['root', 'admin', 'password', 'toor', '', '123456', 'pass'],
    'user': ['user', 'password', '123456', 'pass'],
    'guest': ['guest', '', 'password', 'pass'],
    'support': ['support', 'password', 'admin'],
    
    // IoT/Smart Devices
    'pi': ['raspberry', 'pi'],
    'ubnt': ['ubnt'],
    'cisco': ['cisco'],
    'netgear': ['password', 'admin'],
    'linksys': ['admin', 'password'],
    'dlink': ['admin', ''],
    'tplink': ['admin', 'admin'],
    
    // Cameras/Security
    'admin': ['12345', '123456', 'admin123', 'camera', 'security'],
    'operator': ['operator', 'admin'],
    'viewer': ['viewer', 'guest'],
    
    // Printers
    'admin': ['access', 'printer', 'hp', 'canon', 'brother'],
    'service': ['service', 'admin'],
    
    // Database/Services
    'postgres': ['postgres', 'password', 'admin'],
    'mysql': ['mysql', 'password', 'root'],
    'oracle': ['oracle', 'password'],
    'sa': ['sa', 'password', 'admin'],
    
    // Common default combinations
    'administrator': ['administrator', 'password', 'admin'],
    'test': ['test', 'password', '123456'],
    'demo': ['demo', 'password', 'test']
};

// Known vulnerable ports and services (enhanced)
const VULNERABLE_PORTS = {
    21: { service: 'FTP', risk: 'high', description: 'FTP servers often have weak authentication', checkSSL: false },
    22: { service: 'SSH', risk: 'medium', description: 'SSH with weak passwords is vulnerable to brute force', checkSSL: false },
    23: { service: 'Telnet', risk: 'critical', description: 'Unencrypted remote access protocol', checkSSL: false },
    25: { service: 'SMTP', risk: 'medium', description: 'Mail server potentially exposed', checkSSL: false },
    53: { service: 'DNS', risk: 'medium', description: 'DNS servers can be used for amplification attacks', checkSSL: false },
    80: { service: 'HTTP', risk: 'medium', description: 'Unencrypted web interface', checkSSL: false },
    110: { service: 'POP3', risk: 'medium', description: 'Unencrypted email protocol', checkSSL: false },
    143: { service: 'IMAP', risk: 'medium', description: 'Unencrypted email protocol', checkSSL: false },
    161: { service: 'SNMP', risk: 'high', description: 'Network management protocol often with default community strings', checkSSL: false },
    443: { service: 'HTTPS', risk: 'low', description: 'Encrypted web interface', checkSSL: true },
    993: { service: 'IMAPS', risk: 'low', description: 'Encrypted email protocol', checkSSL: true },
    995: { service: 'POP3S', risk: 'low', description: 'Encrypted email protocol', checkSSL: true },
    1433: { service: 'SQL Server', risk: 'high', description: 'Database server potentially exposed', checkSSL: false },
    3306: { service: 'MySQL', risk: 'high', description: 'Database server potentially exposed', checkSSL: false },
    3389: { service: 'RDP', risk: 'high', description: 'Remote desktop with potential weak authentication', checkSSL: false },
    5432: { service: 'PostgreSQL', risk: 'high', description: 'Database server potentially exposed', checkSSL: false },
    5900: { service: 'VNC', risk: 'high', description: 'Remote desktop often with weak passwords', checkSSL: false },
    8080: { service: 'HTTP-Alt', risk: 'medium', description: 'Alternative web port, often admin interfaces', checkSSL: false },
    8443: { service: 'HTTPS-Alt', risk: 'medium', description: 'Alternative HTTPS port', checkSSL: true },
    9100: { service: 'Printer', risk: 'medium', description: 'Network printer with potential default access', checkSSL: false }
};

// Device manufacturer vulnerability patterns (enhanced)
const DEVICE_VULNERABILITIES = {
    'Brother': {
        type: 'printer',
        commonIssues: ['Default admin password', 'Unencrypted web interface', 'Firmware updates needed'],
        defaultCreds: [['admin', 'access'], ['admin', ''], ['admin', 'brother']],
        webPorts: [80, 443]
    },
    'HP': {
        type: 'printer',
        commonIssues: ['Default admin password', 'Open SNMP', 'Firmware vulnerabilities'],
        defaultCreds: [['admin', 'admin'], ['admin', ''], ['admin', 'hp']],
        webPorts: [80, 443, 8080]
    },
    'Canon': {
        type: 'printer',
        commonIssues: ['Default admin password', 'Unencrypted protocols'],
        defaultCreds: [['ADMIN', 'canon'], ['admin', ''], ['admin', 'canon']],
        webPorts: [80, 443]
    },
    'D-Link': {
        type: 'router',
        commonIssues: ['Default admin credentials', 'Weak WPS', 'Firmware vulnerabilities'],
        defaultCreds: [['admin', 'admin'], ['admin', ''], ['admin', 'password']],
        webPorts: [80, 443, 8080]
    },
    'Netgear': {
        type: 'router',
        commonIssues: ['Default credentials', 'Remote management enabled', 'UPnP vulnerabilities'],
        defaultCreds: [['admin', 'password'], ['admin', 'admin'], ['admin', 'netgear']],
        webPorts: [80, 443, 8080]
    },
    'Linksys': {
        type: 'router',
        commonIssues: ['Default credentials', 'WPS vulnerabilities', 'Remote access'],
        defaultCreds: [['admin', 'admin'], ['admin', ''], ['admin', 'linksys']],
        webPorts: [80, 443, 8080]
    },
    'TP-Link': {
        type: 'router',
        commonIssues: ['Default credentials', 'Management interface exposure', 'Firmware issues'],
        defaultCreds: [['admin', 'admin'], ['admin', 'password'], ['admin', 'tplink']],
        webPorts: [80, 443, 8080]
    },
    'Hikvision': {
        type: 'camera',
        commonIssues: ['Default passwords', 'Unencrypted streams', 'Backdoor vulnerabilities'],
        defaultCreds: [['admin', '12345'], ['admin', 'admin'], ['admin', 'hikvision']],
        webPorts: [80, 443, 8000, 8080]
    },
    'Dahua': {
        type: 'camera',
        commonIssues: ['Weak authentication', 'Default credentials', 'Remote code execution'],
        defaultCreds: [['admin', 'admin'], ['admin', ''], ['admin', 'dahua']],
        webPorts: [80, 443, 37777]
    }
};

// SSL/TLS Certificate Checker
async function checkSSLCertificate(host, port = 443) {
    return new Promise((resolve) => {
        const options = {
            host: host,
            port: port,
            method: 'GET',
            rejectUnauthorized: false, // Don't reject self-signed certs, we want to analyze them
            timeout: 5000
        };

        console.log(`🔒 Checking SSL certificate for ${host}:${port}...`);

        const req = https.request(options, (res) => {
            const cert = res.socket.getPeerCertificate(true);
            
            if (!cert || Object.keys(cert).length === 0) {
                resolve({
                    hasSSL: false,
                    error: 'No certificate found'
                });
                return;
            }

            const now = new Date();
            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const daysUntilExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

            const sslInfo = {
                hasSSL: true,
                subject: cert.subject,
                issuer: cert.issuer,
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                daysUntilExpiry: daysUntilExpiry,
                fingerprint: cert.fingerprint,
                serialNumber: cert.serialNumber,
                selfSigned: cert.issuer.CN === cert.subject.CN,
                expired: now > validTo,
                notYetValid: now < validFrom,
                weakSignature: cert.sigalg && cert.sigalg.includes('sha1'),
                keyLength: cert.bits || 'Unknown'
            };

            // Determine SSL security issues
            sslInfo.issues = [];
            if (sslInfo.selfSigned) {
                sslInfo.issues.push('Self-signed certificate detected');
            }
            if (sslInfo.expired) {
                sslInfo.issues.push('Certificate has expired');
            }
            if (sslInfo.notYetValid) {
                sslInfo.issues.push('Certificate not yet valid');
            }
            if (sslInfo.daysUntilExpiry <= 30 && sslInfo.daysUntilExpiry > 0) {
                sslInfo.issues.push(`Certificate expires in ${sslInfo.daysUntilExpiry} days`);
            }
            if (sslInfo.weakSignature) {
                sslInfo.issues.push('Weak signature algorithm (SHA-1)');
            }
            if (sslInfo.keyLength < 2048) {
                sslInfo.issues.push(`Weak key length (${sslInfo.keyLength} bits)`);
            }

            resolve(sslInfo);
        });

        req.on('error', (error) => {
            resolve({
                hasSSL: false,
                error: error.message
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({
                hasSSL: false,
                error: 'SSL check timeout'
            });
        });

        req.setTimeout(5000);
        req.end();
    });
}

// Enhanced credential testing function
async function testDefaultCredentials(host, port, service) {
    const results = {
        testedCredentials: 0,
        vulnerableCredentials: [],
        credentialIssues: []
    };

    console.log(`🔑 Testing default credentials for ${service} on ${host}:${port}...`);

    // Get device-specific credentials if available
    let credentialsToTest = [];
    
    // Add general service credentials
    Object.entries(DEFAULT_CREDENTIALS).forEach(([username, passwords]) => {
        passwords.forEach(password => {
            credentialsToTest.push([username, password]);
        });
    });

    // Add common combinations
    const commonCombos = [
        ['admin', 'admin'],
        ['admin', 'password'],
        ['admin', ''],
        ['root', 'root'],
        ['guest', 'guest'],
        ['user', 'user'],
        ['test', 'test']
    ];
    
    credentialsToTest = [...credentialsToTest, ...commonCombos];
    
    // Remove duplicates
    credentialsToTest = credentialsToTest.filter((combo, index, self) => 
        index === self.findIndex(t => t[0] === combo[0] && t[1] === combo[1])
    );

    // Limit testing to prevent timeouts (test most common ones)
    credentialsToTest = credentialsToTest.slice(0, 20);

    // Test HTTP Basic Auth for web services
    if (port === 80 || port === 8080 || port === 443 || port === 8443) {
        for (const [username, password] of credentialsToTest) {
            try {
                const authResult = await testHTTPAuth(host, port, username, password, port === 443 || port === 8443);
                results.testedCredentials++;
                
                if (authResult.vulnerable) {
                    results.vulnerableCredentials.push({
                        username,
                        password,
                        service: 'HTTP Basic Auth',
                        evidence: authResult.evidence
                    });
                }
            } catch (error) {
                // Continue testing other credentials
            }
        }
    }

    // Test Telnet credentials
    if (port === 23) {
        for (const [username, password] of credentialsToTest.slice(0, 10)) {
            try {
                const telnetResult = await testTelnetAuth(host, port, username, password);
                results.testedCredentials++;
                
                if (telnetResult.vulnerable) {
                    results.vulnerableCredentials.push({
                        username,
                        password,
                        service: 'Telnet',
                        evidence: telnetResult.evidence
                    });
                }
            } catch (error) {
                // Continue testing
            }
        }
    }

    // Add credential security recommendations
    if (results.vulnerableCredentials.length > 0) {
        results.credentialIssues.push(`Found ${results.vulnerableCredentials.length} default credential(s)`);
        results.credentialIssues.push('Change default passwords immediately');
        results.credentialIssues.push('Implement strong password policies');
    }

    return results;
}

// HTTP Basic Authentication tester
async function testHTTPAuth(host, port, username, password, useSSL = false) {
    return new Promise((resolve) => {
        const protocol = useSSL ? https : http;
        const auth = Buffer.from(`${username}:${password}`).toString('base64');
        
        const options = {
            hostname: host,
            port: port,
            path: '/',
            method: 'GET',
            headers: {
                'Authorization': `Basic ${auth}`,
                'User-Agent': 'DeviceScout-SecurityScanner'
            },
            timeout: 3000,
            rejectUnauthorized: false
        };

        const req = protocol.request(options, (res) => {
            // Check if authentication was successful
            if (res.statusCode === 200 || res.statusCode === 302) {
                resolve({
                    vulnerable: true,
                    evidence: `HTTP ${res.statusCode} response with credentials ${username}:${password}`
                });
            } else {
                resolve({ vulnerable: false });
            }
        });

        req.on('error', () => {
            resolve({ vulnerable: false });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ vulnerable: false });
        });

        req.setTimeout(3000);
        req.end();
    });
}

// Telnet authentication tester
async function testTelnetAuth(host, port, username, password) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';
        let authAttempted = false;

        socket.setTimeout(5000);

        socket.connect(port, host, () => {
            // Connected to Telnet
        });

        socket.on('data', (chunk) => {
            data += chunk.toString();
            
            // Look for login prompt
            if ((data.includes('login:') || data.includes('Username:')) && !authAttempted) {
                authAttempted = true;
                socket.write(username + '\r\n');
            } else if (data.includes('Password:') || data.includes('password:')) {
                socket.write(password + '\r\n');
            } else if (data.includes('$') || data.includes('#') || data.includes('>')) {
                // Looks like we got a shell prompt - vulnerable!
                socket.destroy();
                resolve({
                    vulnerable: true,
                    evidence: `Telnet login successful with ${username}:${password}`
                });
                return;
            }
        });

        socket.on('error', () => {
            resolve({ vulnerable: false });
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve({ vulnerable: false });
        });

        socket.on('close', () => {
            resolve({ vulnerable: false });
        });
    });
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

// Fast port scan with enhanced security checking
function fastPortScanWithSecurity(host) {
    return new Promise((resolve, reject) => {
        console.log(`🔍 Enhanced security scan on ${host}...`);
        
        // Only scan most common ports for speed
        const commonPorts = '21,22,23,53,80,110,143,443,993,995,3389,5900,8080,8443,9100';
        const nmapScan = new nmap.NmapScan(host, `-p ${commonPorts} --open -T4`);
        
        // Set timeout to prevent hanging
        const timeout = setTimeout(() => {
            console.log(`⏰ Port scan timeout for ${host}`);
            resolve({ host: host, openPorts: [], timeout: true });
        }, 15000); // 15 second timeout for security checks
        
        nmapScan.on('complete', async function(data) {
            clearTimeout(timeout);
            
            let scanResult = { host: host, openPorts: [] };
            
            if (data && data.length > 0) {
                scanResult = data[0];
            }

            // Enhanced security checking for open ports
            if (scanResult.openPorts && scanResult.openPorts.length > 0) {
                for (let portInfo of scanResult.openPorts) {
                    const port = portInfo.port;
                    const service = VULNERABLE_PORTS[port];
                    
                    if (service) {
                        portInfo.service = service.service;
                        portInfo.risk = service.risk;
                        portInfo.description = service.description;
                        
                        // Perform SSL certificate check for HTTPS services
                        if (service.checkSSL) {
                            try {
                                console.log(`🔒 Checking SSL for ${host}:${port}...`);
                                const sslInfo = await checkSSLCertificate(host, port);
                                portInfo.sslInfo = sslInfo;
                            } catch (error) {
                                console.error(`❌ SSL check failed for ${host}:${port}:`, error.message);
                                portInfo.sslInfo = { hasSSL: false, error: error.message };
                            }
                        }
                        
                        // Test default credentials
                        try {
                            console.log(`🔑 Testing credentials for ${host}:${port}...`);
                            const credentialResults = await testDefaultCredentials(host, port, service.service);
                            portInfo.credentialTest = credentialResults;
                        } catch (error) {
                            console.error(`❌ Credential test failed for ${host}:${port}:`, error.message);
                            portInfo.credentialTest = { testedCredentials: 0, vulnerableCredentials: [], credentialIssues: [] };
                        }
                    }
                }
            }
            
            resolve(scanResult);
        });
        
        nmapScan.on('error', function(error) {
            clearTimeout(timeout);
            console.error(`❌ Port scan failed for ${host}:`, error.message);
            resolve({ host: host, openPorts: [], error: error.message });
        });
        
        nmapScan.startScan();
    });
}

// Enhanced security analysis with new checks
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

    // Analyze open ports with enhanced security checks
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

                // SSL/TLS specific vulnerabilities
                if (portInfo.sslInfo) {
                    if (portInfo.sslInfo.issues && portInfo.sslInfo.issues.length > 0) {
                        portInfo.sslInfo.issues.forEach(issue => {
                            vulnerabilities.push(`SSL/TLS Issue: ${issue}`);
                            if (issue.includes('expired') || issue.includes('self-signed')) {
                                riskScore += 20;
                            } else {
                                riskScore += 10;
                            }
                        });
                        recommendations.push(`Fix SSL/TLS certificate issues on port ${port}`);
                    }
                }

                // Default credential vulnerabilities
                if (portInfo.credentialTest && portInfo.credentialTest.vulnerableCredentials.length > 0) {
                    portInfo.credentialTest.vulnerableCredentials.forEach(cred => {
                        vulnerabilities.push(`Default credentials found: ${cred.username}:${cred.password} (${cred.service})`);
                        riskScore += 35; // High risk for default credentials
                    });
                    recommendations.push(`Change default passwords on ${vulnInfo.service} service (port ${port})`);
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
    let sslIssues = 0;
    let defaultCredentialIssues = 0;
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

        // Count SSL and credential issues
        if (device.openPorts) {
            device.openPorts.forEach(port => {
                if (port.sslInfo && port.sslInfo.issues && port.sslInfo.issues.length > 0) {
                    sslIssues++;
                }
                if (port.credentialTest && port.credentialTest.vulnerableCredentials.length > 0) {
                    defaultCredentialIssues++;
                }
            });
        }
    });

    const averageRisk = devices.length > 0 ? totalRisk / devices.length : 0;
    const networkScore = Math.max(0, 100 - averageRisk);

    // Enhanced network-level recommendations
    if (highRiskDevices > 0) {
        networkRecommendations.push(`${highRiskDevices} device(s) require immediate security attention`);
    }
    
    if (criticalVulnerabilities > 0) {
        networkRecommendations.push(`${criticalVulnerabilities} device(s) have critical security vulnerabilities`);
    }

    if (defaultCredentialIssues > 0) {
        networkRecommendations.push(`${defaultCredentialIssues} device(s) using default credentials - change immediately`);
    }

    if (sslIssues > 0) {
        networkRecommendations.push(`${sslIssues} SSL/TLS certificate issue(s) detected`);
    }
    
    if (devices.length > 20) {
        networkRecommendations.push('Large number of devices detected - consider network segmentation');
    }

    return {
        score: Math.round(networkScore),
        level: getRiskLevel(100 - networkScore),
        highRiskDevices,
        criticalVulnerabilities,
        sslIssues,
        defaultCredentialIssues,
        totalDevices: devices.length,
        recommendations: networkRecommendations
    };
}

// Enhanced network scan with SSL and credential testing
function scanNetworkWithEnhancedSecurity(subnet) {
    return new Promise(async (resolve, reject) => {
        try {
            console.log(`🔍 Starting ENHANCED security scan of: ${subnet}`);
            
            // First, do a quick discovery scan
            const quickscan = new nmap.QuickScan(subnet);
            
            quickscan.on('complete', async function(discoveredDevices) {
                console.log(`✅ Discovery completed! Found ${discoveredDevices.length} devices`);
                
                const enhancedDevices = [];
                
                // Process devices with enhanced security scanning
                for (let i = 0; i < discoveredDevices.length; i++) {
                    const device = discoveredDevices[i];
                    console.log(`🔍 Enhanced analysis of device ${i + 1}/${discoveredDevices.length}: ${device.ip}`);
                    
                    try {
                        // Enhanced port scan with security checks
                        let portScanData = { openPorts: [] };
                        
                        // Do enhanced scan on all devices with known vendors or open ports
                        portScanData = await fastPortScanWithSecurity(device.ip);
                        
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
                        
                        // Perform enhanced security analysis
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
                                vulnerabilities: ['Enhanced scan failed - basic assessment only'],
                                recommendations: ['Retry enhanced scan for complete analysis'],
                                riskScore: 25,
                                securityLevel: 'Medium'
                            }
                        };
                        
                        enhancedDevices.push(basicDevice);
                    }
                }
                
                // Calculate overall network security with enhanced metrics
                const networkSecurity = calculateNetworkSecurity(enhancedDevices);
                
                console.log(`✅ ENHANCED security scan completed!`);
                console.log(`📊 Network Security Score: ${networkSecurity.score}/100 (${networkSecurity.level})`);
                console.log(`⚠️  High Risk Devices: ${networkSecurity.highRiskDevices}`);
                console.log(`🚨 Critical Vulnerabilities: ${networkSecurity.criticalVulnerabilities}`);
                console.log(`🔒 SSL Issues: ${networkSecurity.sslIssues}`);
                console.log(`🔑 Default Credential Issues: ${networkSecurity.defaultCredentialIssues}`);
                
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
            console.error('❌ Enhanced scan failed:', error.message);
            reject(error);
        }
    });
}

module.exports = {
    getNetworkInfo,
    testNmap,
    scanNetwork: scanNetworkWithEnhancedSecurity
};