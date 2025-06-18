const express = require('express');
const router = express.Router();
const { getNetworkInfo, testNmap } = require('../utils/networkScanner');

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

module.exports = router;