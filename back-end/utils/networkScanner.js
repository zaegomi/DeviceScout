const nmap = require('node-nmap');
const os = require('os');

// Get current network information
function getNetworkInfo() {
    return new Promise((resolve, reject) => {
        try {
            const interfaces = os.networkInterfaces();
            let networkInfo = null;

            // Look for active network interface (usually WiFi or Ethernet)
            for (const [name, networks] of Object.entries(interfaces)) {
                for (const network of networks) {
                    // Skip loopback and internal interfaces
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

// Scan network for devices
function scanNetwork(subnet) {
    return new Promise((resolve, reject) => {
        console.log(`🔍 Scanning subnet: ${subnet}`);
        
        const quickscan = new nmap.QuickScan(subnet);
        
        quickscan.on('complete', function(data) {
            console.log('✅ Scan completed');
            
            const devices = data.map(device => ({
                ip: device.ip,
                hostname: device.hostname || 'Unknown',
                mac: device.mac || 'Unknown',
                vendor: device.vendor || 'Unknown',
                state: device.state || 'up',
                openPorts: device.openPorts || [],
                lastSeen: new Date().toISOString()
            }));
            
            console.log(`📱 Found ${devices.length} devices`);
            resolve(devices);
        });
        
        quickscan.on('error', function(error) {
            console.error('❌ Scan error:', error);
            reject(error);
        });
        
        // Start the scan
        quickscan.startScan();
    });
}

module.exports = {
    scanNetwork,
    getNetworkInfo
};