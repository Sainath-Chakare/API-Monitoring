// // server.js
// const express = require('express');
// const mongoose = require('mongoose');
// const morgan = require('morgan');
// const axios = require('axios');
// const cors = require('cors');
// const bodyParser = require('body-parser');
// const dotenv = require('dotenv');
// const http = require('http');
// const { Server } = require('socket.io');

// // Load environment variables
// dotenv.config();

// // Initialize Express
// const app = express();

// // Middleware
// app.use(morgan('combined'));
// app.use(bodyParser.json());
// app.use(cors());

// // Create HTTP server for socket.io
// const server = http.createServer(app);
// const io = new Server(server);

// // MongoDB connection
// mongoose.connect(process.env.MONGO_URI, {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// })
// .then(() => console.log("MongoDB connected"))
// .catch(err => console.log("MongoDB connection error:", err));

// // Define MongoDB schema and model for logging threats
// const LogSchema = new mongoose.Schema({
//   ip: String,
//   url: String,
//   location: Object,
//   virusTotalReport: Object,
//   shodanReport: Object,
//   threatLevel: String,
//   timestamp: { type: Date, default: Date.now }
// });

// const Log = mongoose.model('Log', LogSchema);

// // Socket.io setup
// io.on('connection', (socket) => {
//   console.log('New client connected');
//   socket.on('disconnect', () => {
//     console.log('Client disconnected');
//   });
// });

// // Helper function to fetch data from external APIs
// const fetchThreatData = async (ip, url) => {
//     try {
//         let ipinfoResponse = null;
//         let virusTotalResponse = null;
//         let shodanResponse = null;
//         let threatLevel = 'safe';
    
//         // IPinfo API - Fetch geographical information only if IP is provided
//         if (ip) {
//             ipinfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_API_KEY}`);
//         }
    
//         // VirusTotal API - Analyze the URL only if URL is provided
//         if (url) {
//             virusTotalResponse = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${process.env.VIRUSTOTAL_API_KEY}&resource=${url}`);
//         }
    
//         // Shodan API - Get threat intelligence only if IP is provided
//         if (ip) {
//             try {
//               shodanResponse = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`);
//             } catch (error) {
//               console.error(`Error fetching Shodan data: ${error.response?.data?.error || error.message}`);
//               // Handle specific Shodan errors (like 403) here
//               shodanResponse = { error: error.response?.data?.error || 'Unknown error from Shodan' };
//             }
//         }
    
//         // Determine threat level based on the available results (example logic)
//         if ((virusTotalResponse && virusTotalResponse.data.positives > 0) || 
//             (shodanResponse && shodanResponse.data.ports && shodanResponse.data.ports.length > 0)) {
//             threatLevel = 'malicious';
//         }
    
//         return {
//             ipinfo: ipinfoResponse ? ipinfoResponse.data : null,
//             virusTotal: virusTotalResponse ? virusTotalResponse.data : null,
//             shodan: shodanResponse ? shodanResponse.data : null,
//             threatLevel
//         };
    
//     } catch (error) {
//         console.error("Error fetching threat data:", error);
//         return null;
//     }
// };

// // API route to log and analyze requests
// app.post('/api/log', async (req, res) => {
//     const { ip, url } = req.body;

//     if (!ip && !url) {
//         return res.status(400).json({ message: 'IP or URL is required' });
//     }

//     // Fetch threat intelligence data
//     const threatData = await fetchThreatData(ip, url);

//     if (!threatData) {
//         return res.status(500).json({ message: 'Error fetching threat data' });
//     }

//     // Create a new log entry in MongoDB
//     const newLog = new Log({
//         ip,
//         url,
//         location: threatData.ipinfo,
//         virusTotalReport: threatData.virusTotal,
//         shodanReport: threatData.shodan,
//         threatLevel: threatData.threatLevel
//     });

//     try {
//         await newLog.save();
//         io.emit('newThreatLog', newLog); // Emit new log to frontend via socket.io
//         res.status(201).json(newLog);
//     } catch (error) {
//         res.status(500).json({ message: 'Error saving log' });
//     }
// });

// // Start the server
// const PORT = process.env.PORT || 5000;
// server.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });


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
const { GoogleGenerativeAI } = require('@google/generative-ai'); // Import Gemini SDK

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();
app.use(morgan('combined'));
app.use(bodyParser.json());
app.use(cors());

const server = http.createServer(app);
const io = new Server(server);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.log("MongoDB connection error:", err));

// Initialize Gemini API
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Define MongoDB schema and model for logging threats
const LogSchema = new mongoose.Schema({
  ip: String,
  url: String,
  location: Object,
  virusTotalReport: Object,
  shodanReport: Object,
  threatLevel: String,
  geminiSummary: String,
  timestamp: { type: Date, default: Date.now }
});

const Log = mongoose.model('Log', LogSchema);

// Helper function to fetch data from external APIs
const fetchThreatData = async (ip, url) => {
  try {
      let ipinfoResponse = null;
      let virusTotalResponse = null;
      let shodanResponse = null;
      let threatLevel = 'safe';

      if (ip) {
          ipinfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_API_KEY}`);
      }
      if (url) {
          virusTotalResponse = await axios.get(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${process.env.VIRUSTOTAL_API_KEY}&resource=${url}`);
      }
      if (ip) {
          shodanResponse = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`);
      }

      if ((virusTotalResponse && virusTotalResponse.data.positives > 0) || 
          (shodanResponse && shodanResponse.data.ports && shodanResponse.data.ports.length > 0)) {
          threatLevel = 'malicious';
      }

      const geminiSummary = await generateGeminiSummary(ipinfoResponse?.data, virusTotalResponse?.data, shodanResponse?.data);
      console.log("Gemini Summary Returned:", geminiSummary);  // Log to verify summary content

      return {
          ipinfo: ipinfoResponse ? ipinfoResponse.data : null,
          virusTotal: virusTotalResponse ? virusTotalResponse.data : null,
          shodan: shodanResponse ? shodanResponse.data : null,
          threatLevel,
          geminiSummary
      };
  
  } catch (error) {
      console.error("Error fetching threat data:", error);
      return null;
  }
};


// Function to generate a summary using Gemini
const generateGeminiSummary = async (ipinfo, virusTotal, shodan) => {
  const prompt = `
      Based on the following threat intelligence data, highlight the key parameters:
      - IP Information: ${JSON.stringify(ipinfo)}
      - VirusTotal Report: ${JSON.stringify(virusTotal)}
      - Shodan Report: ${JSON.stringify(shodan)}
      Summarize the main risks and insights from this data.
  `;

  try {
      const result = await model.generateContent({
          contents: [
              {
                  parts: [{ text: prompt }]
              }
          ]
      });

      // Access the nested text within `candidates[0].content.parts[0].text`
      const summary = result.response.candidates[0]?.content?.parts[0]?.text;
      console.log("Generated Gemini Summary:", summary); // Log to verify summary text
      return summary || "No summary generated by Gemini.";
  } catch (error) {
      console.error("Error generating summary with Gemini:", error);
      return "Error retrieving summary from Gemini.";
  }
};




// API route to log and analyze requests
app.post('/api/log', async (req, res) => {
  const { ip, url } = req.body;

  if (!ip && !url) {
      return res.status(400).json({ message: 'IP or URL is required' });
  }

  const threatData = await fetchThreatData(ip, url);

  if (!threatData) {
      return res.status(500).json({ message: 'Error fetching threat data' });
  }

  const newLog = new Log({
      ip,
      url,
      location: threatData.ipinfo,
      virusTotalReport: threatData.virusTotal,
      shodanReport: threatData.shodan,
      threatLevel: threatData.threatLevel,
      geminiSummary: threatData.geminiSummary // Confirm this field is populated
  });

  console.log("New Log Entry:", newLog); // Log to verify `geminiSummary` before saving

  try {
      await newLog.save();
      io.emit('newThreatLog', newLog);
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
