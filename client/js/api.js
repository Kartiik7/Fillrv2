// API_URL is provided by env.js (loaded before this script)
const API_URL = (typeof ENV !== 'undefined' && ENV.API_URL) || 'http://localhost:5000/api';

async function apiRequest(endpoint, method = 'GET', body = null) {
    const headers = {
        'Content-Type': 'application/json'
    };

    const token = localStorage.getItem('token');
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        method,
        headers,
    };

    if (body) {
        config.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_URL}${endpoint}`, config);
        const data = await response.json();
        return { status: response.status, data };
    } catch (error) {
        console.error('API Error:', error);
        return { status: 500, data: { success: false, message: 'Network/Server Error' } };
    }
}

function logout() {
    localStorage.removeItem('token');
    window.location.href = '/login';
}
