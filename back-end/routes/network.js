const express = require('express');
const router = express.Router();
const { getNetworkInfo, testNmap, scanNetwork } = require('../utils/networkScanner');

// GET /api/network-info - Get current network information
router.get('/network-info', async (req, res) => {
    try {
        console.log('📡 Getting network information...');
        const networkInfo = await getNetworkInfo();
        
        res.json({
            success: true,
            network: networkInfo,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Network info error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// GET /api/test-nmap - Test nmap installation
router.get('/test-nmap', async (req, res) => {
    try {
        console.log('🧪 Testing nmap...');
        await testNmap();
        
        res.json({
            success: true,
            message: 'Nmap is working correctly!',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Nmap test error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// GET /api/scan - Perform comprehensive network device scan with security assessment
router.get('/scan', async (req, res) => {
    try {
        console.log('🔍 Starting comprehensive network security scan...');
        
        // Get network info first
        const networkInfo = await getNetworkInfo();
        console.log(`📡 Scanning network: ${networkInfo.subnet}`);
        
        // Perform the enhanced scan with security assessment
        const scanResults = await scanNetwork(networkInfo.subnet);
        
        console.log(`✅ Enhanced scan completed successfully!`);
        console.log(`📱 Found ${scanResults.devices.length} devices`);
        console.log(`🔒 Network Security Score: ${scanResults.networkSecurity.score}/100`);
        
        // Calculate summary statistics
        const vulnerabilityStats = calculateVulnerabilityStats(scanResults.devices);
        
        res.json({
            success: true,
            network: networkInfo,
            devices: scanResults.devices,
            deviceCount: scanResults.devices.length,
            networkSecurity: scanResults.networkSecurity,
            vulnerabilityStats: vulnerabilityStats,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('❌ Enhanced scan failed:', error.message);
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// GET /api/device/:ip - Get detailed information for a specific device
router.get('/device/:ip', async (req, res) => {
    try {
        const deviceIP = req.params.ip;
        console.log(`🔍 Getting detailed info for device: ${deviceIP}`);
        
        // This would typically fetch from a database or cache
        // For now, we'll return a placeholder response
        res.json({
            success: true,
            message: 'Device detail endpoint - implementation pending',
            device: {
                ip: deviceIP,
                lastScanned: new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('❌ Device detail error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// GET /api/security-report - Generate comprehensive security report
router.get('/security-report', async (req, res) => {
    try {
        console.log('📊 Generating security report...');
        
        // This would typically aggregate data from recent scans
        // For now, return a placeholder
        res.json({
            success: true,
            message: 'Security report endpoint - implementation pending',
            report: {
                generatedAt: new Date().toISOString(),
                summary: 'Comprehensive security analysis'
            }
        });
        
    } catch (error) {
        console.error('❌ Security report error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Helper function to calculate vulnerability statistics
function calculateVulnerabilityStats(devices) {
    const stats = {
        totalDevices: devices.length,
        securityLevels: {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0
        },
        commonVulnerabilities: {},
        averageRiskScore: 0,
        devicesNeedingAttention: 0
    };
    
    let totalRiskScore = 0;
    
    devices.forEach(device => {
        if (device.security) {
            // Count security levels
            const level = device.security.securityLevel;
            if (stats.securityLevels[level] !== undefined) {
                stats.securityLevels[level]++;
            }
            
            // Track risk scores
            totalRiskScore += device.security.riskScore;
            
            // Count devices needing attention (Medium risk or higher)
            if (['Critical', 'High', 'Medium'].includes(level)) {
                stats.devicesNeedingAttention++;
            }
            
            // Count common vulnerabilities
            device.security.vulnerabilities.forEach(vuln => {
                // Simplify vulnerability names for grouping
                const vulnType = vuln.split(' ')[0] || vuln;
                stats.commonVulnerabilities[vulnType] = (stats.commonVulnerabilities[vulnType] || 0) + 1;
            });
        }
    });
    
    // Calculate average risk score
    stats.averageRiskScore = devices.length > 0 ? Math.round(totalRiskScore / devices.length) : 0;
    
    // Get top 5 most common vulnerabilities
    const sortedVulns = Object.entries(stats.commonVulnerabilities)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5);
    
    stats.topVulnerabilities = sortedVulns.map(([vuln, count]) => ({
        vulnerability: vuln,
        count: count,
        percentage: Math.round((count / devices.length) * 100)
    }));
    
    return stats;
}

module.exports = router;