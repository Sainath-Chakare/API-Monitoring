// import React, { useState } from 'react';
// import axios from 'axios';
// import './App.css';

// function App() {
//   // State for managing input, loading status, and the response data
//   const [ip, setIp] = useState('');
//   const [url, setUrl] = useState('');
//   const [responseData, setResponseData] = useState(null);
//   const [loading, setLoading] = useState(false);
//   const [error, setError] = useState(null);

//   // Handle form submission
//   const handleSubmit = async (e) => {
//     e.preventDefault();
//     setLoading(true);
//     setError(null);

//     try {
//       const response = await axios.post('http://localhost:5000/api/log', { ip, url });
//       console.log("Response Data:", response.data); // Log response data
//       setResponseData(response.data);
//     } catch (err) {
//       setError('Error fetching threat data. Please try again.');
//     } finally {
//       setLoading(false);
//     }
//   };

//   const parseSummary = (summary) => {
//     if (!summary) return null;
//     const lines = summary.split('\n');
//     const parsedElements = [];

//     lines.forEach((line, index) => {
//       if (line.startsWith('## ')) {
//         parsedElements.push(<h3 key={index}>{line.replace('## ', '')}</h3>);
//       } else if (line.startsWith('* ')) {
//         parsedElements.push(<li key={index}>{line.replace('* ', '')}</li>);
//       } else if (line.startsWith('**')) {
//         parsedElements.push(<strong key={index}>{line.replace(/\*\*/g, '')}</strong>);
//       } else if (line.trim() === '') {
//         parsedElements.push(<br key={index} />);
//       } else {
//         parsedElements.push(<p key={index}>{line}</p>);
//       }
//     });

//     return (
//       <div className="gemini-summary">
//         {parsedElements}
//       </div>
//     );
//   };

//   return (
//     <div className="App">
//       <h1>API Threat Monitoring</h1>
//       <form onSubmit={handleSubmit}>
//         <div>
//           <label>IP Address:</label>
//           <input
//             type="text"
//             placeholder="Enter IP address (optional)"
//             value={ip}
//             onChange={(e) => setIp(e.target.value)}
//           />
//         </div>
//         <div>
//           <label>URL:</label>
//           <input
//             type="text"
//             placeholder="Enter URL (optional)"
//             value={url}
//             onChange={(e) => setUrl(e.target.value)}
//           />
//         </div>
//         <button type="submit" disabled={loading}>
//           {loading ? 'Analyzing...' : 'Analyze'}
//         </button>
//       </form>

//       {error && <p className="error">{error}</p>}

//       {responseData && (
//         <div className="response">
//           <h2>Threat Analysis Report</h2>
//           <p><strong>Threat Level:</strong> {responseData.threatLevel}</p>

//           {responseData.geminiSummary ? (
//             <div>
//               <h3>Gemini Summary</h3>
//               {parseSummary(responseData.geminiSummary)}
//             </div>
//           ) : (
//             <p>Gemini summary not available</p>
//           )}

//           {responseData.ip && (
//             <div>
//               <h3>IP Information</h3>
//               <p><strong>IP:</strong> {responseData.ip}</p>
//               <p><strong>Location:</strong> {responseData.location?.city}, {responseData.location?.region}, {responseData.location?.country}</p>
//               <p><strong>Organization:</strong> {responseData.location?.org}</p>
//             </div>
//           )}

//           {responseData.url && (
//             <div>
//               <h3>URL Information</h3>
//               <p><strong>URL:</strong> {responseData.url}</p>
//               <p><strong>VirusTotal Report:</strong> {responseData.virusTotalReport?.positives} positives out of {responseData.virusTotalReport?.total} scans</p>
//               <a href={responseData.virusTotalReport?.permalink} target="_blank" rel="noopener noreferrer">View Full VirusTotal Report</a>
//             </div>
//           )}

//           {responseData.shodanReport && (
//             <div>
//               <h3>Shodan Information</h3>
//               <p><strong>Open Ports:</strong> {responseData.shodanReport.ports?.join(', ') || 'None'}</p>
//               <p><strong>ISP:</strong> {responseData.shodanReport.isp}</p>
//               <p><strong>Country:</strong> {responseData.shodanReport.country_name}</p>
//               <p><strong>Hostnames:</strong> {responseData.shodanReport.hostnames?.join(', ') || 'None'}</p>
//             </div>
//           )}
//         </div>
//       )}
//     </div>
//   );
// }

// export default App;


import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [ip, setIp] = useState('');
  const [url, setUrl] = useState('');
  const [responseData, setResponseData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [cleanedParameters, setCleanedParameters] = useState('');
  const [mitigationRules, setMitigationRules] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post('http://localhost:5000/api/log', { ip, url });
      setResponseData(response.data);
    } catch (err) {
      setError('Error fetching threat data. Please try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCleanedParameters = async () => {
    if (responseData) {
      try {
        const response = await axios.post('http://localhost:5000/api/cleanedParameters', { data: responseData });
        let cleanedParams = response.data.cleanedParameters || "No data available";

        // Append the VirusTotal URL if it exists
        if (responseData.virusTotalReport && responseData.virusTotalReport.permalink) {
          cleanedParams += `<br><br><strong>VirusTotal Report Link:</strong> <a href="${responseData.virusTotalReport.permalink}" target="_blank">View Full Report on VirusTotal</a>`;
        }

        setCleanedParameters(cleanedParams);
      } catch (error) {
        console.error("Error generating cleaned parameters:", error);
        setCleanedParameters("Error retrieving cleaned parameters.");
      }
    } else {
      setCleanedParameters("No threat data available to process.");
    }
  };

  const handleMitigationRules = async () => {
    if (cleanedParameters) {
      try {
        const response = await axios.post('http://localhost:5000/api/firewallMitigationRules', { parameters: cleanedParameters });
        setMitigationRules(response.data.mitigationRules || "No rules generated.");
      } catch (error) {
        console.error("Error generating firewall rules:", error);
        setMitigationRules("Error retrieving firewall rules.");
      }
    } else {
      setMitigationRules("No cleaned parameters available to generate rules.");
    }
  };

  const renderFormattedData = (data) => {
    const formattedData = data.replace(/\n/g, '<br>').replace(/\*\*/g, '<strong>').replace(/\*/g, '<li>');
    return { __html: formattedData };
  };

  return (
    <div className="App">
      <h1>API Threat Monitoring & Response Application</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label>IP Address:</label>
          <input type="text" placeholder="Enter IP address (optional)" value={ip} onChange={(e) => setIp(e.target.value)} />
        </div>
        <div>
          <label>URL:</label>
          <input type="text" placeholder="Enter URL (optional)" value={url} onChange={(e) => setUrl(e.target.value)} />
        </div>
        <button type="submit" disabled={loading}>
          {loading ? 'Analyzing...' : 'Analyze'}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      {responseData && (
  <div className="response">
    <h2>Threat Analysis Report</h2>
    <p><strong>Threat Level:</strong> {responseData.threatLevel}</p>

    <div className="button-group">
      <button onClick={handleCleanedParameters}>Generate Cleaned Parameters</button>
      <button onClick={handleMitigationRules}>Generate Firewall Mitigation Rules</button>
    </div>

    {cleanedParameters && (
      <div className="section-box">
        <div className="section-header">Cleaned Parameters</div>
        <div dangerouslySetInnerHTML={renderFormattedData(cleanedParameters)} />
      </div>
    )}

    {/* Optional separator line */}
    {cleanedParameters && mitigationRules && <hr className="separator" />}

    {mitigationRules && (
      <div className="section-box">
        <div className="section-header">Firewall Mitigation Rules</div>
        <div dangerouslySetInnerHTML={renderFormattedData(mitigationRules)} />
      </div>
    )}
  </div>
)}

    </div>
  );
}

export default App;
