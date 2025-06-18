const nmap = require('node-nmap');
const os = require('os');

// Get current network information
function getNetworkInfo() {
    return new Promise((resolve, reject) => {
        try {
            console.log('📡 Detecting network interfaces...');
            const interfaces = os.networkInterfaces();
            let networkInfo = null;

            // Look for active network interface
            for (const [name, networks] of Object.entries(interfaces)) {
                for (const network of networks) {
                    // Skip loopback and internal interfaces, look for IPv4
                    if (!network.internal && network.family === 'IPv4') {
                        const ip = network.address;
                        const netmask = network.netmask;
                        
                        // Calculate subnet (basic implementation)
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
        
        // Test with a simple localhost scan
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

// Scan network for devices
function scanNetwork(subnet) {
    return new Promise((resolve, reject) => {
        console.log(`🔍 Starting network scan of: ${subnet}`);
        
        const quickscan = new nmap.QuickScan(subnet);
        
        quickscan.on('complete', function(data) {
            console.log(`✅ Scan completed! Found ${data.length} devices`);
            
            const devices = data.map((device, index) => {
                console.log(`📱 Device ${index + 1}: ${device.ip} - ${device.hostname || 'Unknown'}`);
                
                return {
                    ip: device.ip,
                    hostname: device.hostname || 'Unknown',
                    mac: device.mac || 'Unknown',
                    vendor: device.vendor || 'Unknown',
                    state: device.state || 'up',
                    openPorts: device.openPorts || [],
                    osNmap: device.osNmap || 'Unknown',
                    lastSeen: new Date().toISOString()
                };
            });
            
            resolve(devices);
        });
        
        quickscan.on('error', function(error) {
            console.error('❌ Scan error:', error.message);
            reject(error);
        });
        
        console.log('⏳ Scanning in progress...');
        quickscan.startScan();
    });
}

module.exports = {
    getNetworkInfo,
    testNmap,
    scanNetwork
};