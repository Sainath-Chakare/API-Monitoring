// server.js
const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();

// Middleware
app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(cors());

// Create HTTP server for socket.io
const server = http.createServer(app);
const io = new Server(server);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.log("MongoDB connection error:", err));

// Define MongoDB schema and model for logging threats
const LogSchema = new mongoose.Schema({
  ip: String,
  url: String,
  location: Object,
  virusTotalReport: Object,
  shodanReport: Object,
  threatLevel: String,
  timestamp: { type: Date, default: Date.now }
});

const Log = mongoose.model('Log', LogSchema);

// Socket.io setup
io.on('connection', (socket) => {
  console.log('New client connected');
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Helper function to fetch data from external APIs
const fetchThreatData = async (ip, url) => {
    try {
        let ipinfoResponse = null;
        let virusTotalResponse = null;
        let shodanResponse = null;
        let threatLevel = 'safe';
    
        // IPinfo API - Fetch geographical information only if IP is provided
        if (ip) {
            ipinfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_API_KEY}`);
        }
    
        // VirusTotal API - Analyze the URL only if URL is provided
        if (url) {
            virusTotalResponse = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${process.env.VIRUSTOTAL_API_KEY}&resource=${url}`);
        }
    
        // Shodan API - Get threat intelligence only if IP is provided
        if (ip) {
            try {
              shodanResponse = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`);
            } catch (error) {
              console.error(`Error fetching Shodan data: ${error.response?.data?.error || error.message}`);
              // Handle specific Shodan errors (like 403) here
              shodanResponse = { error: error.response?.data?.error || 'Unknown error from Shodan' };
            }
        }
    
        // Determine threat level based on the available results (example logic)
        if ((virusTotalResponse && virusTotalResponse.data.positives > 0) || 
            (shodanResponse && shodanResponse.data.ports && shodanResponse.data.ports.length > 0)) {
            threatLevel = 'malicious';
        }
    
        return {
            ipinfo: ipinfoResponse ? ipinfoResponse.data : null,
            virusTotal: virusTotalResponse ? virusTotalResponse.data : null,
            shodan: shodanResponse ? shodanResponse.data : null,
            threatLevel
        };
    
    } catch (error) {
        console.error("Error fetching threat data:", error);
        return null;
    }
};

// API route to log and analyze requests
app.post('/api/log', async (req, res) => {
    const { ip, url } = req.body;

    if (!ip && !url) {
        return res.status(400).json({ message: 'IP or URL is required' });
    }

    // Fetch threat intelligence data
    const threatData = await fetchThreatData(ip, url);

    if (!threatData) {
        return res.status(500).json({ message: 'Error fetching threat data' });
    }

    // Create a new log entry in MongoDB
    const newLog = new Log({
        ip,
        url,
        location: threatData.ipinfo,
        virusTotalReport: threatData.virusTotal,
        shodanReport: threatData.shodan,
        threatLevel: threatData.threatLevel
    });

    try {
        await newLog.save();
        io.emit('newThreatLog', newLog); // Emit new log to frontend via socket.io
        res.status(201).json(newLog);
    } catch (error) {
        res.status(500).json({ message: 'Error saving log' });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});