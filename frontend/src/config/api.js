// Backend API base URL — override via VITE_API_URL in .env
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export default API_BASE;
