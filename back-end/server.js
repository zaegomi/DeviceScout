const express = require('express');
const cors = require('cors');

// Import routes
const networkRoutes = require('./routes/network');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', networkRoutes);

// Test route
app.get('/', (req, res) => {
    res.json({ 
        message: 'DeviceScout Backend API is running!',
        timestamp: new Date().toISOString(),
        availableEndpoints: [
            'GET /api/network-info',
            'GET /api/test-nmap',
            'GET /api/scan'  // Add this line
        ]
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 DeviceScout Backend running on http://localhost:${PORT}`);
    console.log(`📡 Test endpoints:`);
    console.log(`   - http://localhost:${PORT}/api/network-info`);
    console.log(`   - http://localhost:${PORT}/api/test-nmap`);
    console.log(`   - http://localhost:${PORT}/api/scan`);  // Add this line
});