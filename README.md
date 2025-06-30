# DeviceScout
## Network Security Made Simple

DeviceScout is a comprehensive IoT device discovery and security assessment tool that helps users identify connected devices on their network and evaluate potential security vulnerabilities. Now featuring **enhanced SSL/TLS certificate analysis** and **default credential testing** for enterprise-grade security assessment.

![DeviceScout Logo](logo.png)

## 🌟 Enhanced Features

- **Real-time Network Scanning** - Discover all devices connected to your network using Nmap
- **Advanced Device Identification** - Identify device types, manufacturers, and operating systems
- **Enhanced Security Assessment** - Comprehensive vulnerability detection with SSL/TLS and credential analysis
- **SSL/TLS Certificate Analysis** - Certificate validation, expiration monitoring, and security issue detection
- **Default Credential Testing** - Automated testing for common default passwords across multiple protocols
- **Professional Reporting** - PDF reports, CSV exports, and print-ready summaries
- **User-friendly Interface** - Clean, professional web interface accessible to non-technical users
- **Data Persistence** - Scan results survive page refreshes and browser sessions
- **Detailed Device Analysis** - Click any device for comprehensive security breakdown

## 🔒 Advanced Security Capabilities

### **SSL/TLS Certificate Security**
- **Certificate Expiration Monitoring** - Alerts for certificates expiring within 30 days
- **Self-Signed Certificate Detection** - Identifies potentially insecure certificates
- **Weak Cryptography Analysis** - Detects SHA-1 signatures and weak key lengths
- **Certificate Chain Validation** - Comprehensive issuer and subject analysis
- **Security Issue Reporting** - Clear identification of SSL/TLS vulnerabilities

### **Default Credential Testing**
- **Multi-Protocol Support** - HTTP Basic Auth, Telnet, and service-specific testing
- **Comprehensive Database** - 200+ default credential combinations
- **Vendor-Specific Testing** - Targeted checks for routers, printers, cameras, IoT devices
- **Evidence Collection** - Detailed reporting of vulnerable credentials found
- **Smart Testing Logic** - Prevents account lockouts while ensuring thorough coverage

### **Enhanced Risk Assessment**
- **Dynamic Risk Scoring** - SSL issues and default credentials heavily weighted
- **Vendor-Specific Vulnerabilities** - Tailored security checks for major manufacturers
- **Port Service Analysis** - Risk assessment for each open network service
- **Professional Recommendations** - Actionable security guidance for each device

## 🏗️ Architecture

DeviceScout consists of two main components:

- **Frontend** - React-based web interface with enhanced security visualization
- **Backend** - Node.js API server with Nmap integration and advanced security testing

## 📋 Prerequisites

### System Requirements
- **Node.js** (v14 or higher)
- **npm** (Node Package Manager)
- **Nmap** (Network scanning tool)

### Installing Nmap

**Windows:**
1. Download from: https://nmap.org/download.html#windows
2. Run the installer and ensure "Add Nmap to PATH" is checked
3. Restart your terminal after installation

**macOS:**
```bash
brew install nmap
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Verify Installation:**
```bash
nmap --version
```

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/devicescout.git
cd devicescout
```

### 2. Backend Setup

```bash
# Navigate to backend directory
cd devicescout-backend

# Install dependencies
npm install

# Start the backend server
npm run dev
```

The backend will run on `http://localhost:3001`

### 3. Frontend Setup

```bash
# In a new terminal, navigate to frontend directory
cd devicescout-frontend

# Start the frontend server using Live Server (VS Code) or:
npx live-server
```

**Alternative Frontend Options:**
- **VS Code Live Server Extension:** Right-click `index.html` → "Open with Live Server"
- **Python:** `python -m http.server 8000`

## 🖥️ Usage

### Basic Operation
1. **Ensure both servers are running:**
   - Backend: `http://localhost:3001`
   - Frontend: `http://localhost:5500` (or your live server port)

2. **Open the frontend** in your web browser

3. **Click "Click to Scan"** to start enhanced network discovery

4. **Wait for scan completion** (60-120 seconds for comprehensive security analysis)

### Navigation & Features
5. **View results across multiple pages:**
   - **Dashboard** - Network overview with security metrics and export options
   - **Devices** - Complete device list with security badges (click any device for detailed analysis)
   - **Security** - Network-wide security assessment with professional reporting
   - **Device Details** - Comprehensive per-device security analysis

### Enhanced Security Analysis
6. **Device Detail Pages include:**
   - **SSL/TLS Certificate Analysis** - Certificate validation and security issues
   - **Default Credential Results** - Vulnerable username/password combinations found
   - **Port Security Assessment** - Risk analysis for each open service
   - **Vendor-Specific Recommendations** - Tailored security guidance

### Export & Reporting
7. **Professional reporting options:**
   - **PDF Reports** - Executive summaries with detailed security analysis
   - **CSV Exports** - Complete device inventories for spreadsheet analysis
   - **Print Summaries** - Clean reports for management presentations

## 📡 API Endpoints

The backend provides the following endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /` | API status and health check |
| `GET /api/network-info` | Get current network information |
| `GET /api/test-nmap` | Test Nmap installation |
| `GET /api/scan` | Perform comprehensive network device scan with enhanced security analysis |

## 🛠️ Development

### Project Structure

```
DeviceScout/
├── devicescout-frontend/
│   ├── index.html              # Main React application with enhanced UI
│   ├── logo.png               # Application logo
│   └── package.json
└── devicescout-backend/
    ├── server.js               # Express server
    ├── package.json
    ├── routes/
    │   └── network.js          # API routes with enhanced security endpoints
    └── utils/
        └── networkScanner.js   # Enhanced Nmap integration with SSL/TLS and credential testing
```

### Technology Stack

**Frontend:**
- HTML5 / CSS3
- JavaScript (ES6+)
- React 18 (via CDN)
- jsPDF (PDF generation)
- Responsive Design

**Backend:**
- Node.js
- Express.js
- Nmap (via node-nmap package)
- HTTPS/HTTP modules for SSL testing
- Net module for credential testing
- CORS enabled for cross-origin requests

### Testing the Setup

**Test Backend:**
```bash
# Check if backend is running
curl http://localhost:3001

# Test network detection
curl http://localhost:3001/api/network-info

# Test Nmap integration
curl http://localhost:3001/api/test-nmap

# Test enhanced security scan
curl http://localhost:3001/api/scan
```

## 🔒 Security Considerations

- **Local Network Only** - DeviceScout scans your local network subnet
- **No External Data Transmission** - All scanning and analysis performed locally
- **Responsible Testing** - Credential testing limited to prevent account lockouts
- **Admin Privileges** - Enhanced scanning features may require elevated permissions
- **Firewall Configuration** - Ensure your firewall allows local network communication
- **SSL/TLS Analysis** - Certificate checking does not store or transmit sensitive data

## 🐛 Troubleshooting

### Backend Issues

**"Nmap not found" errors:**
- Verify Nmap installation: `nmap --version`
- Ensure Nmap is in your system PATH
- Restart terminal after installation (especially on Windows)

**Enhanced scan takes longer:**
- Normal enhanced scan time: 60-120 seconds for comprehensive analysis
- SSL and credential testing add processing time
- Large networks may take several minutes for complete assessment

**SSL connection errors:**
- Some devices may reject SSL connections from scanning tools
- Self-signed certificates will generate warnings but still be analyzed
- Network firewalls may block SSL analysis attempts

**Permission errors:**
- Enhanced security features may require administrator/root privileges
- Run terminal as administrator (Windows) or use `sudo` (Mac/Linux)
- Some credential testing requires elevated network access

### Frontend Issues

**Cannot connect to backend:**
- Verify backend is running on `http://localhost:3001`
- Check browser console for CORS errors
- Ensure both frontend and backend are running

**Export features not working:**
- Ensure jsPDF library is loaded (check browser console)
- Verify scan data exists before attempting export
- Check browser's download/popup blocking settings

### Scanning Issues

**Enhanced scan timeout:**
- Increase timeout values in scanner configuration
- Skip problematic devices and continue with scan
- Check network connectivity and device responsiveness

**No SSL information:**
- Ensure target devices have HTTPS services running
- Verify devices are not blocking SSL connections
- Check that certificates are properly configured on target devices

**Credential testing fails:**
- Verify network connectivity to target services
- Ensure services accept the tested authentication methods
- Check for rate limiting or intrusion detection systems

## 📈 Performance Notes

- **Enhanced Scan Speed:** 60-120 seconds for comprehensive security analysis
- **Resource Usage:** Higher CPU/memory usage during SSL and credential testing
- **Network Impact:** More thorough scanning generates additional network traffic
- **Concurrent Scans:** Only one enhanced scan should run at a time
- **Data Persistence:** Scan results automatically saved to browser storage

## 📊 Export & Reporting Features

### **PDF Reports Include:**
- Executive summary with network security score
- Complete device inventory with risk assessments
- SSL/TLS certificate analysis results
- Default credential vulnerability findings
- Professional security recommendations
- Compliance-ready formatting

### **CSV Exports Contain:**
- Device name, IP, MAC address, vendor information
- Security level and risk score for each device
- Open ports and service information
- Vulnerability summaries and recommendations
- SSL certificate status and credential test results

### **Print Summaries Feature:**
- Clean, professional formatting
- Key security metrics and findings
- Management-ready presentation format

## 🚀 Enhanced Security Features

### **SSL/TLS Certificate Monitoring**
DeviceScout now automatically analyzes SSL/TLS certificates on HTTPS services:

- **Expiration Alerts:** Warns about certificates expiring within 30 days
- **Security Validation:** Detects self-signed, expired, or weak certificates
- **Compliance Checking:** Identifies certificates using outdated cryptographic standards
- **Chain Analysis:** Validates certificate authority chains and trust relationships

### **Default Credential Detection**
Advanced credential testing across multiple protocols:

- **HTTP Basic Authentication:** Tests web interface login forms
- **Telnet Services:** Validates command-line access credentials
- **Vendor-Specific Testing:** Tailored credential checks for major device manufacturers
- **Evidence Collection:** Documents exactly which credentials were found vulnerable

### **Risk Assessment Enhancements**
- **Weighted Scoring:** SSL issues and default credentials receive high risk scores
- **Vendor Awareness:** Device-specific vulnerability patterns and recommendations
- **Service Analysis:** Port-by-port security assessment with specific guidance
- **Compliance Mapping:** Security findings aligned with industry best practices

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes in the appropriate directory (`devicescout-frontend/` or `devicescout-backend/`)
4. Test your changes thoroughly, especially security features
5. Commit with clear messages: `git commit -am 'Add feature: description'`
6. Push to your branch: `git push origin feature-name`
7. Submit a Pull Request

## 📄 License

MIT License - see LICENSE file for details

## 🚀 Future Enhancements

- **Advanced Vulnerability Scanning** - CVE database integration and exploit analysis
- **Network Topology Visualization** - Interactive network maps with security overlays
- **Historical Tracking** - Security posture trends and improvement tracking
- **Compliance Frameworks** - NIST, ISO 27001, and industry standard alignment
- **Mobile Applications** - iOS/Android apps for remote network monitoring
- **Enterprise Integration** - SIEM integration and centralized management
- **Advanced Analytics** - Machine learning for threat detection and prediction

## 📞 Support

For issues and questions:
- **Create an issue** on GitHub with detailed error information
- **Check the troubleshooting section** above for common solutions
- **Include console output** (both frontend and backend) when reporting bugs
- **Specify network environment** details for enhanced security feature issues

## 🔍 What's New in Enhanced Version

### **Version 2.0 - Enhanced Security Assessment**
- ✅ **SSL/TLS Certificate Analysis** - Comprehensive certificate security validation
- ✅ **Default Credential Testing** - Automated vulnerability detection across protocols
- ✅ **Professional Reporting** - PDF generation with executive summaries
- ✅ **Data Persistence** - Scan results survive browser refreshes
- ✅ **Enhanced UI** - Detailed device analysis pages with security breakdowns
- ✅ **Export Capabilities** - Multiple format support for reporting and analysis
- ✅ **Risk Assessment** - Advanced scoring with SSL and credential weighting
- ✅ **Vendor Intelligence** - Device-specific security recommendations

---

**DeviceScout** - Making enterprise-grade network security accessible to everyone.