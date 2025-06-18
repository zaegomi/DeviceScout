const { useState, useEffect } = React;

function DeviceScout() {
    const [currentPage, setCurrentPage] = useState('start');
    const [isScanning, setIsScanning] = useState(false);
    const [deviceCount, setDeviceCount] = useState(0);
    const [securityScore, setSecurityScore] = useState(40);

    const devices = [
        'Brother Printer',
        'LG Smart TV',
        'iPhone',
        'Kindle'
    ];

    const handleScan = () => {
        setIsScanning(true);
        // Simulate scanning process
        setTimeout(() => {
            setIsScanning(false);
            setDeviceCount(devices.length);
            setCurrentPage('dashboard');
        }, 3000);
    };

    const navigateToPage = (page) => {
        setCurrentPage(page);
    };

    return React.createElement('div', { className: 'app-container' },
        React.createElement('header', { className: 'header' },
            React.createElement('div', { className: 'logo-section' },
                React.createElement('div', { className: 'logo-icon' }),
                React.createElement('div', { className: 'logo-text' },
                    React.createElement('div', { className: 'logo-title' }, 'DeviceScout'),
                    React.createElement('div', { className: 'logo-subtitle' }, 'Network Security Made Simple')
                )
            ),
            
            currentPage !== 'start' && React.createElement('nav', { className: 'nav-buttons' },
                React.createElement('button', {
                    className: `nav-button ${currentPage === 'dashboard' ? 'active' : ''}`,
                    onClick: () => navigateToPage('dashboard')
                }, 'Dashboard'),
                React.createElement('button', {
                    className: `nav-button ${currentPage === 'devices' ? 'active' : ''}`,
                    onClick: () => navigateToPage('devices')
                }, 'Devices'),
                React.createElement('button', {
                    className: `nav-button ${currentPage === 'security' ? 'active' : ''}`,
                    onClick: () => navigateToPage('security')
                }, 'Security'),
                React.createElement('button', {
                    className: `nav-button ${currentPage === 'newscan' ? 'active' : ''}`,
                    onClick: () => setCurrentPage('start')
                }, 'New Scan')
            )
        ),

        React.createElement('main', { className: 'main-content' },
            // Start Page
            React.createElement('div', { className: `page ${currentPage === 'start' ? 'active' : ''}` },
                React.createElement('div', { className: 'start-page' },
                    React.createElement('div', { className: 'scan-circle', onClick: handleScan },
                        React.createElement('div', { className: 'scan-text' },
                            isScanning ? 
                                React.createElement('div', null,
                                    React.createElement('div', { className: 'loading-animation' }),
                                    React.createElement('div', { style: { marginTop: '10px', fontSize: '1.2rem' } }, 'Scanning...')
                                ) :
                                'Click to Scan'
                        )
                    ),
                    !isScanning && React.createElement('p', {
                        style: { fontSize: '1.2rem', color: '#64748b', maxWidth: '600px' }
                    }, 'Welcome to DeviceScout! Click the button above to start scanning your network for connected devices and security vulnerabilities.')
                )
            ),

            // Dashboard Page
            React.createElement('div', { className: `page ${currentPage === 'dashboard' ? 'active' : ''}` },
                React.createElement('div', { className: 'dashboard-grid' },
                    React.createElement('div', { className: 'dashboard-card' },
                        React.createElement('h2', { className: 'card-title' }, 'Total Devices'),
                        React.createElement('div', { className: 'card-content' },
                            React.createElement('div', { className: 'metric-value' }, deviceCount),
                            React.createElement('div', { className: 'metric-label' }, 'Connected Devices'),
                            React.createElement('div', {
                                style: { fontSize: '0.9rem', color: '#38a169', marginTop: '10px' }
                            }, '✓ All devices discovered')
                        )
                    ),
                    React.createElement('div', { className: 'dashboard-card' },
                        React.createElement('h2', { className: 'card-title' }, 'Security Score'),
                        React.createElement('div', { className: 'card-content' },
                            React.createElement('div', { className: 'metric-value' }, `${securityScore}/100`),
                            React.createElement('div', { className: 'metric-label' }, 'Overall Security'),
                            React.createElement('div', {
                                style: { fontSize: '0.9rem', color: '#e53e3e', marginTop: '10px' }
                            }, '⚠ Needs Attention')
                        )
                    ),
                    React.createElement('div', { className: 'dashboard-card' },
                        React.createElement('h2', { className: 'card-title' }, 'Additional Details'),
                        React.createElement('div', { className: 'card-content' },
                            React.createElement('div', {
                                style: { fontSize: '1.1rem', color: '#2d3748', lineHeight: '1.6' }
                            },
                                React.createElement('div', null, '🔍 Last scan: Just now'),
                                React.createElement('div', null, '⚠ 2 vulnerabilities found'),
                                React.createElement('div', null, '🔒 1 device needs update'),
                                React.createElement('div', null, '📊 Network health: Fair')
                            )
                        )
                    )
                )
            ),

            // Devices Page
            React.createElement('div', { className: `page ${currentPage === 'devices' ? 'active' : ''}` },
                React.createElement('div', { className: 'device-container' },
                    React.createElement('h2', { className: 'device-title' }, 'Device Information'),
                    React.createElement('div', { className: 'device-list' },
                        devices.map((device, index) =>
                            React.createElement('div', {
                                key: index,
                                className: 'device-item'
                            }, device)
                        )
                    ),
                    React.createElement('div', {
                        style: { marginTop: '30px', textAlign: 'center', color: '#64748b' }
                    },
                        React.createElement('p', null, 'Click on any device for detailed information and security analysis')
                    )
                )
            ),

            // Security Page
            React.createElement('div', { className: `page ${currentPage === 'security' ? 'active' : ''}` },
                React.createElement('div', { className: 'security-container' },
                    React.createElement('h2', { className: 'security-title' }, 'Security Assessment'),
                    React.createElement('div', { className: 'security-score' }, `${securityScore}/100`),
                    React.createElement('div', { className: 'security-status' }, 'Poor'),
                    React.createElement('div', { className: 'security-details' },
                        React.createElement('div', { className: 'security-recommendation' },
                            '⚠ Your network security needs immediate attention'
                        ),
                        React.createElement('div', {
                            style: { marginTop: '20px', color: '#4a5568', lineHeight: '1.6' }
                        },
                            React.createElement('div', null, '• 2 devices have outdated firmware'),
                            React.createElement('div', null, '• 1 device using default passwords'),
                            React.createElement('div', null, '• Network encryption could be stronger'),
                            React.createElement('div', null, '• Regular security scans recommended')
                        ),
                        React.createElement('div', {
                            style: { marginTop: '20px', padding: '15px', background: '#e2e8f0', borderRadius: '8px' }
                        },
                            React.createElement('strong', null, 'Recommendation: '),
                            'Update your Brother Printer firmware and change default passwords on all IoT devices.'
                        )
                    )
                )
            )
        )
    );
}

ReactDOM.render(React.createElement(DeviceScout), document.getElementById('root'));