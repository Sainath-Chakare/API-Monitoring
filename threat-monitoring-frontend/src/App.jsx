import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  // State for managing input, loading status, and the response data
  const [ip, setIp] = useState('');
  const [url, setUrl] = useState('');
  const [responseData, setResponseData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post('http://localhost:5000/api/log', { ip, url });
      console.log("Response Data:", response.data); // Log response data
      setResponseData(response.data);
    } catch (err) {
      setError('Error fetching threat data. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const parseSummary = (summary) => {
    if (!summary) return null;
    const lines = summary.split('\n');
    const parsedElements = [];

    lines.forEach((line, index) => {
      if (line.startsWith('## ')) {
        parsedElements.push(<h3 key={index}>{line.replace('## ', '')}</h3>);
      } else if (line.startsWith('* ')) {
        parsedElements.push(<li key={index}>{line.replace('* ', '')}</li>);
      } else if (line.startsWith('**')) {
        parsedElements.push(<strong key={index}>{line.replace(/\*\*/g, '')}</strong>);
      } else if (line.trim() === '') {
        parsedElements.push(<br key={index} />);
      } else {
        parsedElements.push(<p key={index}>{line}</p>);
      }
    });

    return (
      <div className="gemini-summary">
        {parsedElements}
      </div>
    );
  };

  return (
    <div className="App">
      <h1>API Threat Monitoring</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label>IP Address:</label>
          <input
            type="text"
            placeholder="Enter IP address (optional)"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
        </div>
        <div>
          <label>URL:</label>
          <input
            type="text"
            placeholder="Enter URL (optional)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
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

          {responseData.geminiSummary ? (
            <div>
              <h3>Gemini Summary</h3>
              {parseSummary(responseData.geminiSummary)}
            </div>
          ) : (
            <p>Gemini summary not available</p>
          )}

          {responseData.ip && (
            <div>
              <h3>IP Information</h3>
              <p><strong>IP:</strong> {responseData.ip}</p>
              <p><strong>Location:</strong> {responseData.location?.city}, {responseData.location?.region}, {responseData.location?.country}</p>
              <p><strong>Organization:</strong> {responseData.location?.org}</p>
            </div>
          )}

          {responseData.url && (
            <div>
              <h3>URL Information</h3>
              <p><strong>URL:</strong> {responseData.url}</p>
              <p><strong>VirusTotal Report:</strong> {responseData.virusTotalReport?.positives} positives out of {responseData.virusTotalReport?.total} scans</p>
              <a href={responseData.virusTotalReport?.permalink} target="_blank" rel="noopener noreferrer">View Full VirusTotal Report</a>
            </div>
          )}

          {responseData.shodanReport && (
            <div>
              <h3>Shodan Information</h3>
              <p><strong>Open Ports:</strong> {responseData.shodanReport.ports?.join(', ') || 'None'}</p>
              <p><strong>ISP:</strong> {responseData.shodanReport.isp}</p>
              <p><strong>Country:</strong> {responseData.shodanReport.country_name}</p>
              <p><strong>Hostnames:</strong> {responseData.shodanReport.hostnames?.join(', ') || 'None'}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
