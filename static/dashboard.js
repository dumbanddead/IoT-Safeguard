/* ========================================
   IoT Security Dashboard - JavaScript
   Enhanced with Interactive Features & Guided Tour
   ======================================== */

// Global state
let currentSection = 'overview';
let allAlerts = [];
let allDevices = {};
let allRules = [];
let statusChart = null;
let tourActive = false;
let tourStep = 0;
// Pagination for devices
let devicePage = 1;
let devicePageSize = 6;
let deviceTotal = 0;

// Guided tour steps
const tourSteps = [
    {
        target: '.header',
        title: 'Welcome to IoT Security Dashboard',
        text: 'This dashboard provides real-time monitoring of your IoT network security, powered by an AI threat detection engine.'
    },
    {
        target: '[data-tour="nav-overview"]',
        title: '📊 Overview Section',
        text: 'View real-time statistics and key metrics about your network. See total devices, online status, and active threats at a glance.'
    },
    {
        target: '[data-tour="stats-grid"]',
        title: '📈 Live Statistics',
        text: 'These cards show real-time metrics. Green indicates healthy status. Red indicates threats or blocked devices.'
    },
    {
        target: '[data-tour="nav-devices"]',
        title: '📱 Device Monitoring',
        text: 'Monitor individual IoT devices, view their traffic patterns, and take action by blocking suspicious devices.'
    },
    {
        target: '[data-tour="nav-alerts"]',
        title: '⚠️ Threat Alerts',
        text: 'View AI-detected threats in real-time. Each alert shows confidence level and device information. Click "Resolve" to dismiss.'
    },
    {
        target: '[data-tour="nav-topology"]',
        title: '🌐 Network Topology',
        text: 'Visualize your network layout. Drag nodes to reorganize. Different colors represent different device types.'
    },
    {
        target: '[data-tour="nav-firewall"]',
        title: '🔥 Firewall Rules',
        text: 'Configure network access control policies. Define which devices can communicate with each other.'
    }
];

// Utility to show a banner overlay when backend is missing
function showBackendError(message) {
    const overlay = document.getElementById('errorOverlay');
    if (!overlay) return;
    overlay.querySelector('.error-message p').textContent = message;
    overlay.classList.remove('hidden');
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    // detect incorrect protocol (file:// or nothing)
    if (window.location.protocol === 'file:' || window.location.protocol === 'about:') {
        showBackendError('You are viewing the page locally. Run the Flask server and open it via http://localhost:5000/');
        return;
    }

    initializeDashboard();
    setupEventListeners();
    setupGuidedTour();
    startAutoRefresh();
    // Wire Load more button
    const loadMoreBtn = document.getElementById('loadMoreDevices');
    if (loadMoreBtn) loadMoreBtn.addEventListener('click', loadMoreDevices);

    // Open SSE connection for live updates
    try {
        const es = new EventSource('/api/stream');
        es.addEventListener('alerts', (e) => {
            try {
                const alerts = JSON.parse(e.data);
                allAlerts = alerts.concat(allAlerts.filter(a => !alerts.find(n=>n.id===a.id)));
                renderAlerts();
                loadStats();
            } catch (err) { console.error('SSE alerts parse', err); }
        });
        es.addEventListener('devices', (e) => {
            try {
                const devs = JSON.parse(e.data);
                devs.forEach(d => {
                    allDevices[d.mac] = Object.assign({}, allDevices[d.mac] || {}, d);
                });
                renderDevices();
                loadStats();
            } catch (err) { console.error('SSE devices parse', err); }
        });
        es.addEventListener('error', (e) => { console.warn('SSE error', e); });
    } catch (err) {
        console.warn('SSE not available', err);
    }
});

// modify loadStats to surface backend errors
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) {
            throw new Error(`status ${response.status}`);
        }
        const stats = await response.json();

        document.getElementById('stat-total-devices').textContent = stats.total_devices;
        document.getElementById('stat-online-devices').textContent = stats.online_devices;
        document.getElementById('stat-blocked-devices').textContent = stats.blocked_devices;
        document.getElementById('stat-active-alerts').textContent = stats.active_alerts;

        // Update status chart
        updateStatusChart(stats);
    } catch (error) {
        console.error('Error loading stats:', error);
        showBackendError('Unable to contact backend API. Is the server running?');
    }
}

function initializeDashboard() {
    // Load initial data
    loadStats();
    devicePage = 1;
    allDevices = {};
    loadDevices();
    loadAlerts();
    loadTopology();
    loadFirewallRules();
    updateTimestamp();
    
    // Show welcome notification
    showNotification('Welcome to IoT Security Dashboard!', 'Click "Guided Tour" to learn all features.', 'success');
    // Initialize theme
    initTheme();
}

function setupEventListeners() {
    // Navigation with smooth transitions
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            switchSection(section);
        });
    });

    // Device cards hover effects
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('btn-block')) {
            blockDevice(e.target.dataset.mac);
        } else if (e.target.classList.contains('btn-unblock')) {
            unblockDevice(e.target.dataset.mac);
        }
    });

    // Firewall modal
    const ruleModal = document.getElementById('ruleModal');
    const addRuleBtn = document.getElementById('addRuleBtn');
    const closeBtn = ruleModal.querySelector('.close');

    addRuleBtn.addEventListener('click', () => {
        ruleModal.classList.remove('hidden');
    });

    closeBtn.addEventListener('click', () => {
        ruleModal.classList.add('hidden');
    });

    window.addEventListener('click', (e) => {
        if (e.target === ruleModal) {
            ruleModal.classList.add('hidden');
        }
    });

    // Rule form
    document.getElementById('ruleForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const rule = {
            source_mac: document.getElementById('ruleSrcMac').value,
            dest_mac: document.getElementById('ruleDestMac').value,
            action: document.getElementById('ruleAction').value,
            priority: parseInt(document.getElementById('rulePriority').value)
        };
        
        try {
            const response = await fetch('/api/firewall-rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(rule)
            });
            
            if (response.ok) {
                ruleModal.classList.add('hidden');
                document.getElementById('ruleForm').reset();
                loadFirewallRules();
                showNotification('Firewall rule created successfully! ✅', '', 'success');
            }
        } catch (error) {
            console.error('Error adding rule:', error);
            showNotification('Error creating rule ❌', error.message, 'error');
        }
    });

    // Alert filters
    document.getElementById('alertFilter').addEventListener('input', filterAlerts);
    document.getElementById('alertStatusFilter').addEventListener('change', filterAlerts);

    // Help button and panel
    const helpBtn = document.getElementById('helpBtn');
    const helpPanel = document.getElementById('helpPanel');
    const helpPanelClose = document.getElementById('helpPanelClose');

    helpBtn.addEventListener('click', () => {
        helpPanel.classList.toggle('active');
    });

    helpPanelClose.addEventListener('click', () => {
        helpPanel.classList.remove('active');
    });
}

function switchSection(section) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`[data-section="${section}"]`).classList.add('active');

    // Update content
    document.querySelectorAll('.section').forEach(s => {
        s.classList.remove('active');
    });
    const targetSection = document.getElementById(section);
    targetSection.classList.add('active');
    targetSection.classList.add('highlight');

    currentSection = section;

    // Load section-specific data
    if (section === 'topology') {
        setTimeout(() => renderTopology(), 100);
    }
}

// ========== API CALLS ==========

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();

        document.getElementById('stat-total-devices').textContent = stats.total_devices;
        document.getElementById('stat-online-devices').textContent = stats.online_devices;
        document.getElementById('stat-blocked-devices').textContent = stats.blocked_devices;
        document.getElementById('stat-active-alerts').textContent = stats.active_alerts;

        // Update status chart
        updateStatusChart(stats);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadDevices() {
    try {
        const response = await fetch(`/api/devices?page=${devicePage}&page_size=${devicePageSize}`);
        const data = await response.json();
        deviceTotal = data.total || 0;

        // merge loaded items into allDevices map
        (data.items || []).forEach(d => {
            // ensure mac key exists
            const mac = d.mac || d.mac_address || d.mac_address;
            allDevices[d.mac] = Object.assign({}, d, { mac: d.mac });
        });

        renderDevices();
        // hide Load more if done
        const loadMoreBtn = document.getElementById('loadMoreDevices');
        if (loadMoreBtn) {
            const loaded = Object.keys(allDevices).length;
            loadMoreBtn.style.display = loaded < deviceTotal ? 'inline-block' : 'none';
        }
    } catch (error) {
        console.error('Error loading devices:', error);
    }
}

async function loadMoreDevices() {
    // increment page and fetch
    devicePage += 1;
    await loadDevices();
}

async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts');
        allAlerts = await response.json();
        renderAlerts();
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function loadTopology() {
    try {
        const response = await fetch('/api/topology');
        window.topologyData = await response.json();
    } catch (error) {
        console.error('Error loading topology:', error);
    }
}

async function loadFirewallRules() {
    try {
        const response = await fetch('/api/firewall-rules');
        allRules = await response.json();
        renderFirewallRules();
    } catch (error) {
        console.error('Error loading firewall rules:', error);
    }
}

// ========== RENDERING FUNCTIONS ==========

function renderDevices() {
    const container = document.getElementById('devicesContainer');
    container.innerHTML = '';
    // Apply search and sort filters
    const searchText = (document.getElementById('deviceSearch') || { value: '' }).value.toLowerCase();
    const sortMode = (document.getElementById('deviceSort') || { value: '' }).value;

    let devicesArr = Object.entries(allDevices);
    // filter
    devicesArr = devicesArr.filter(([mac, device]) => {
        const txt = `${device.id} ${mac} ${device.ip || ''}`.toLowerCase();
        return txt.includes(searchText);
    });

    // sort
    if (sortMode === 'online') {
        devicesArr.sort((a,b) => (b[1].status === 'online') - (a[1].status === 'online'));
    } else if (sortMode === 'blocked') {
        devicesArr.sort((a,b) => (b[1].blocked ? 1:0) - (a[1].blocked ? 1:0));
    } else if (sortMode === 'traffic_desc') {
        devicesArr.sort((a,b) => (b[1].traffic_bytes || 0) - (a[1].traffic_bytes || 0));
    }

    devicesArr.forEach(([mac, device]) => {
        const card = document.createElement('div');
        card.className = `device-card ${device.blocked ? 'blocked' : ''}`;
        card.style.cursor = 'pointer';
        const statusClass = device.status === 'online' ? '' : 'offline';

        // Choose avatar
        let avatar = '/static/images/unknown.svg';
        if (device.type === 'camera') avatar = '/static/images/camera.svg';
        else if (device.type === 'sensor') avatar = '/static/images/sensor.svg';
        else if (device.type === 'gateway') avatar = '/static/images/gateway.svg';
        else if (device.type === 'actuator') avatar = '/static/images/actuator.svg';

        card.innerHTML = `
            <div class="device-main">
                <img src="${avatar}" class="device-avatar" alt="${device.id}">
                <div class="device-meta">
                    <div class="device-header">
                        <span class="device-name">${device.id}</span>
                        <div class="device-status ${statusClass}"></div>
                    </div>
                    <div class="device-info">MAC: ${mac}</div>
                    <div class="device-info">IP: ${device.ip || 'N/A'}</div>
                    <div class="device-info">Status: <strong>${device.status.toUpperCase()}</strong></div>
                    <div class="device-stats" style="margin-top:8px;">
                        <div class="device-stat">
                            <div class="device-stat-value">${device.packet_count}</div>
                            <div class="device-stat-label">Packets</div>
                        </div>
                        <div class="device-stat">
                            <div class="device-stat-value">${formatBytes(device.traffic_bytes)}</div>
                            <div class="device-stat-label">Traffic</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="device-actions" style="margin-top:10px; display:flex; gap:10px;">
                ${device.blocked ? 
                    `<button class="btn-unblock" data-mac="${mac}" onclick="unblockDevice('${mac}')">✓ Unblock</button>` :
                    `<button class="btn-block" data-mac="${mac}" onclick="blockDevice('${mac}')">⛔ Block</button>`
                }
            </div>
        `;

        // Click to show modal
        card.addEventListener('click', (e) => {
            // prevent clicks on the action buttons from opening modal
            if (e.target.tagName.toLowerCase() === 'button') return;
            showDeviceModal(mac, device);
        });
        
        // Add hover effect
        card.addEventListener('mouseenter', () => {
            if (!device.blocked) card.style.transform = 'translateY(-8px)';
        });
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0)';
        });
        
        container.appendChild(card);
    });
}

    // Device modal functions
    function showDeviceModal(mac, device) {
        const modal = document.getElementById('deviceModal');
        const img = document.getElementById('deviceModalImage');
        const name = document.getElementById('deviceModalName');
        const macEl = document.getElementById('deviceModalMac');
        const ipEl = document.getElementById('deviceModalIp');
        const statusEl = document.getElementById('deviceModalStatus');
        const trafficEl = document.getElementById('deviceModalTraffic');
        const blockBtn = document.getElementById('deviceModalBlock');
        const unblockBtn = document.getElementById('deviceModalUnblock');

        let avatar = '/static/images/unknown.svg';
        if (device.type === 'camera') avatar = '/static/images/camera.svg';
        else if (device.type === 'sensor') avatar = '/static/images/sensor.svg';
        else if (device.type === 'gateway') avatar = '/static/images/gateway.svg';
        else if (device.type === 'actuator') avatar = '/static/images/actuator.svg';

        img.src = avatar;
        name.textContent = device.id;
        macEl.textContent = `MAC: ${mac}`;
        ipEl.textContent = `IP: ${device.ip || 'N/A'}`;
        statusEl.textContent = `Status: ${device.status.toUpperCase()}`;
        trafficEl.textContent = `Traffic: ${formatBytes(device.traffic_bytes || 0)}`;

        // wire modal buttons
        blockBtn.onclick = async () => { await blockDevice(mac); modal.classList.add('hidden'); };
        unblockBtn.onclick = async () => { await unblockDevice(mac); modal.classList.add('hidden'); };

        modal.classList.remove('hidden');
    }

    // modal close
    document.addEventListener('click', (e) => {
        const modal = document.getElementById('deviceModal');
        if (!modal) return;
        const close = document.getElementById('deviceModalClose');
        if (e.target === modal || e.target === close) {
            modal.classList.add('hidden');
        }
    });

    // wire device search & sort listeners
    document.addEventListener('DOMContentLoaded', () => {
        const search = document.getElementById('deviceSearch');
        const sort = document.getElementById('deviceSort');
        if (search) search.addEventListener('input', () => renderDevices());
        if (sort) sort.addEventListener('change', () => renderDevices());
    });

function renderAlerts() {
    const container = document.getElementById('alertsContainer');
    container.innerHTML = '';

    const filteredAlerts = filterAlertsList(allAlerts);

    if (filteredAlerts.length === 0) {
        container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">✓ No active alerts. Network is secure!</div>';
        return;
    }

    filteredAlerts.forEach((alert, index) => {
        const item = document.createElement('div');
        item.className = `alert-item ${alert.status}`;
        
        const timestamp = new Date(alert.timestamp);
        const timeStr = timestamp.toLocaleTimeString();
        
        item.innerHTML = `
            <div class="alert-content">
                <div class="alert-header">
                    <span class="alert-type">⚠️ ${alert.threat_type}</span>
                    <span class="alert-device">Device: ${alert.device_id || alert.device_mac}</span>
                </div>
                <div>
                    <span class="alert-confidence">Confidence: ${alert.confidence}%</span>
                    <span class="alert-status ${alert.status}">${alert.status.toUpperCase()}</span>
                    <span class="alert-time">${timeStr}</span>
                </div>
                <div style="margin-top: 8px; font-size: 11px; color: #999;">
                    Traffic: ${alert.traffic_bytes || 0} bytes | Packets: ${alert.packet_rate || 0}
                </div>
            </div>
            <div class="alert-actions">
                ${alert.status === 'active' ? 
                    `<button class="btn-resolve" onclick="resolveAlert('${alert.id}')">✓ Resolve</button>` :
                    ''
                }
            </div>
        `;
        
        item.style.animation = `slideIn 0.3s ease ${index * 0.05}s both`;
        container.appendChild(item);
    });
}

function renderFirewallRules() {
    const container = document.getElementById('firewallContainer');
    
    if (allRules.length === 0) {
        container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No firewall rules</div>';
        return;
    }

    let html = `
        <table>
            <thead>
                <tr>
                    <th>Source MAC</th>
                    <th>Destination MAC</th>
                    <th>Action</th>
                    <th>Priority</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;

    allRules.forEach(rule => {
        const actionClass = rule.action === 'allow' ? 'rule-action-allow' : 'rule-action-deny';
        html += `
            <tr>
                <td>${rule.source_mac}</td>
                <td>${rule.dest_mac}</td>
                <td><span class="${actionClass}">${rule.action.toUpperCase()}</span></td>
                <td>${rule.priority}</td>
                <td>
                    <button class="btn-delete-rule" onclick="deleteRule('${rule.id}')">Delete</button>
                </td>
            </tr>
        `;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

function renderTopology() {
    if (!window.topologyData) return;

    const container = document.getElementById('topologyContainer');
    container.innerHTML = '';
    container.style.height = '500px';

    // Convert topologyData into cytoscape elements
    const elements = [];

    (window.topologyData.nodes || []).forEach(n => {
        elements.push({ data: { id: n.id, label: n.label, type: n.type } });
    });
    (window.topologyData.links || []).forEach((l, i) => {
        elements.push({ data: { id: 'e' + i, source: l.source, target: l.target } });
    });

    // Initialize Cytoscape
    const cy = cytoscape({
        container: container,
        elements: elements,
        style: [
            { selector: 'node', style: { 'label': 'data(label)', 'text-valign': 'center', 'color': '#fff', 'text-outline-color': '#000', 'text-outline-width': 2, 'background-color': '#2196F3', 'width': 50, 'height': 50 } },
            { selector: 'node[type="gateway"]', style: { 'background-color': '#4CAF50' } },
            { selector: 'node[type="switch"]', style: { 'background-color': '#0b5fff' } },
            { selector: 'edge', style: { 'width': 3, 'line-color': '#888' } }
        ],
        layout: { name: 'cose', animate: true },
        userZoomingEnabled: true,
        userPanningEnabled: true,
    });

    // Node click -> focus and show info
    cy.on('tap', 'node', function (evt) {
        const node = evt.target;
        const id = node.data('id');
        showNodeInfo(id);
        node.animate({ style: { 'border-width': 4, 'border-color': '#fff' } }, { duration: 300 });
    });

    function showNodeInfo(id) {
        // find device and open devices section with highlight
        if (document.querySelector('[data-section="devices"]')) {
            switchSection('devices');
        }
        // highlight matching device card
        const cards = document.querySelectorAll('.device-card');
        cards.forEach(c => {
            if (c.innerText.includes(id)) {
                c.classList.add('highlight');
                setTimeout(() => c.classList.remove('highlight'), 2000);
            }
        });
    }
}

function updateStatusChart(stats) {
    const ctx = document.getElementById('statusChart');
    if (!ctx) return;

    if (statusChart) {
        statusChart.destroy();
    }

    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Online', 'Blocked'],
            datasets: [{
                data: [stats.online_devices, stats.blocked_devices],
                backgroundColor: ['#4CAF50', '#F44336'],
                borderColor: '#242424',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#e0e0e0',
                        font: { size: 12 }
                    }
                }
            }
        }
    });
}

// ========== ACTION FUNCTIONS ==========

async function blockDevice(mac) {
    try {
        await fetch(`/api/devices/${mac}/block`, { method: 'POST' });
        loadDevices();
        loadStats();
    } catch (error) {
        console.error('Error blocking device:', error);
    }
}

async function unblockDevice(mac) {
    try {
        await fetch(`/api/devices/${mac}/unblock`, { method: 'POST' });
        loadDevices();
        loadStats();
    } catch (error) {
        console.error('Error unblocking device:', error);
    }
}

async function resolveAlert(alertId) {
    try {
        await fetch(`/api/alerts/${alertId}/resolve`, { method: 'POST' });
        loadAlerts();
        loadStats();
    } catch (error) {
        console.error('Error resolving alert:', error);
    }
}

async function deleteRule(ruleId) {
    try {
        await fetch(`/api/firewall-rules/${ruleId}`, { method: 'DELETE' });
        loadFirewallRules();
    } catch (error) {
        console.error('Error deleting rule:', error);
    }
}

// ========== UTILITY FUNCTIONS ==========

function filterAlerts() {
    renderAlerts();
}

function filterAlertsList(alerts) {
    const searchText = document.getElementById('alertFilter').value.toLowerCase();
    const statusFilter = document.getElementById('alertStatusFilter').value;

    return alerts.filter(alert => {
        const matchesSearch = 
            alert.threat_type.toLowerCase().includes(searchText) ||
            alert.device_mac.toLowerCase().includes(searchText);
        
        const matchesStatus = !statusFilter || alert.status === statusFilter;
        
        return matchesSearch && matchesStatus;
    });
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

function updateTimestamp() {
    const now = new Date();
    document.getElementById('timestamp').textContent = now.toLocaleString();
}

function startAutoRefresh() {
    // Refresh stats every 5 seconds
    setInterval(loadStats, 5000);
    
    // Refresh alerts every 3 seconds
    setInterval(() => {
        loadAlerts();
        if (currentSection === 'overview') {
            updateTimestamp();
        }
    }, 3000);
    
    // Refresh devices every 10 seconds
    setInterval(() => {
        if (currentSection === 'devices') {
            loadDevices();
        }
    }, 10000);
}

// ========== NOTIFICATION SYSTEM ==========
function showNotification(title, message, type = 'info') {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <strong>${title}</strong>
        ${message ? `<div style="font-size: 11px; margin-top: 5px; color: #999;">${message}</div>` : ''}
    `;
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.classList.add('exit');
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// ========== GUIDED TOUR SYSTEM ==========
function setupGuidedTour() {
    const startTourBtn = document.getElementById('startTourBtn');
    startTourBtn.addEventListener('click', startGuidedTour);
}

function startGuidedTour() {
    tourActive = true;
    tourStep = 0;
    showTourStep(tourStep);
}

function showTourStep(step) {
    if (step >= tourSteps.length) {
        endGuidedTour();
        return;
    }

    const tourData = tourSteps[step];
    const target = document.querySelector(tourData.target);
    
    if (!target) {
        tourStep++;
        showTourStep(tourStep);
        return;
    }

    // Show overlay
    let overlay = document.getElementById('tourOverlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'tourOverlay';
        overlay.className = 'tour-overlay active';
        document.body.appendChild(overlay);
    } else {
        overlay.classList.add('active');
    }

    // Show spotlight
    let spotlight = document.getElementById('tourSpotlight');
    if (!spotlight) {
        spotlight = document.createElement('div');
        spotlight.id = 'tourSpotlight';
        spotlight.className = 'tour-spotlight';
        document.body.appendChild(spotlight);
    }

    const rect = target.getBoundingClientRect();
    spotlight.style.top = rect.top - 5 + 'px';
    spotlight.style.left = rect.left - 5 + 'px';
    spotlight.style.width = rect.width + 10 + 'px';
    spotlight.style.height = rect.height + 10 + 'px';

    // Show tooltip
    let tooltip = document.getElementById('tourTooltip');
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'tourTooltip';
        tooltip.className = 'tour-tooltip';
        document.body.appendChild(tooltip);
    }

    const tooltipContent = `
        <h3>${tourData.title}</h3>
        <p>${tourData.text}</p>
        <div class="tour-buttons">
            <button class="tour-btn tour-btn-skip" onclick="endGuidedTour()">Skip Tour</button>
            <button class="tour-btn tour-btn-next" onclick="nextTourStep()">
                ${tourStep === tourSteps.length - 1 ? 'Finish' : 'Next →'}
            </button>
        </div>
    `;
    tooltip.innerHTML = tooltipContent;

    // Position tooltip
    tooltip.style.top = Math.min(rect.bottom + 20, window.innerHeight - 200) + 'px';
    tooltip.style.left = Math.max(20, rect.left - 50) + 'px';
}

function nextTourStep() {
    tourStep++;
    showTourStep(tourStep);
}

function endGuidedTour() {
    tourActive = false;
    tourStep = 0;
    
    const overlay = document.getElementById('tourOverlay');
    const spotlight = document.getElementById('tourSpotlight');
    const tooltip = document.getElementById('tourTooltip');
    
    if (overlay) overlay.classList.remove('active');
    if (spotlight) spotlight.style.display = 'none';
    if (tooltip) tooltip.style.display = 'none';
    
    showNotification('Tour Complete! 🎉', 'You now know all the features of the dashboard.', 'success');
}

// ========== THEME TOGGLE ==========
function initTheme() {
    const saved = localStorage.getItem('dashboardTheme') || 'dark';
    applyTheme(saved);
    const btn = document.getElementById('themeToggle');
    if (btn) {
        btn.textContent = saved === 'dark' ? '🌙' : '☀️';
        btn.addEventListener('click', () => {
            const next = (localStorage.getItem('dashboardTheme') || 'dark') === 'dark' ? 'light' : 'dark';
            applyTheme(next);
        });
    }
}

function applyTheme(kind) {
    if (kind === 'light') {
        document.documentElement.classList.add('light-theme');
        localStorage.setItem('dashboardTheme', 'light');
        const btn = document.getElementById('themeToggle'); if (btn) btn.textContent = '☀️';
    } else {
        document.documentElement.classList.remove('light-theme');
        localStorage.setItem('dashboardTheme', 'dark');
        const btn = document.getElementById('themeToggle'); if (btn) btn.textContent = '🌙';
    }
}
