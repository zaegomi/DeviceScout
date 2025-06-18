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

// GET /api/scan - Perform network device scan
router.get('/scan', async (req, res) => {
    try {
        console.log('🔍 Starting network device scan...');
        
        // Get network info first
        const networkInfo = await getNetworkInfo();
        console.log(`📡 Scanning network: ${networkInfo.subnet}`);
        
        // Perform the scan
        const devices = await scanNetwork(networkInfo.subnet);
        
        console.log(`✅ Scan completed successfully! Found ${devices.length} devices`);
        
        res.json({
            success: true,
            network: networkInfo,
            devices: devices,
            deviceCount: devices.length,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('❌ Scan failed:', error.message);
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;