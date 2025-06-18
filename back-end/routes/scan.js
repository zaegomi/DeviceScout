const express = require('express');
const router = express.Router();
const { scanNetwork, getNetworkInfo } = require('../utils/networkScanner');

// GET /api/scan - Start network scan
router.get('/scan', async (req, res) => {
    try {
        console.log('🔍 Starting network scan...');
        
        // Get network information first
        const networkInfo = await getNetworkInfo();
        console.log('📡 Network Info:', networkInfo);
        
        // Scan the network
        const devices = await scanNetwork(networkInfo.subnet);
        
        res.json({
            success: true,
            network: networkInfo,
            devices: devices,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('❌ Scan Error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// GET /api/network-info - Get current network information
router.get('/network-info', async (req, res) => {
    try {
        const networkInfo = await getNetworkInfo();
        res.json({
            success: true,
            network: networkInfo
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;