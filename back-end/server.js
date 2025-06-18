const express = require('express');
const cors = require('cors');
const scanRoutes = require('./routes/scan');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', scanRoutes);

// Test route
app.get('/', (req, res) => {
    res.json({ message: 'DeviceScout Backend API is running!' });
});

app.listen(PORT, () => {
    console.log(`🚀 DeviceScout Backend running on http://localhost:${PORT}`);
});