import axios from 'axios';
import { toast } from 'react-hot-toast';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://lex.aoseudispor.com.br:5000/api'
});

// Interceptor para debug das requisições
api.interceptors.request.use(config => {
    // Debug
    console.log('Configuração da requisição:', {
        method: config.method,
        url: config.url,
        baseURL: config.baseURL,
        fullURL: `${config.baseURL}${config.url}`,
        headers: config.headers
    });
    return config;
});

// Interceptor para adicionar o token de autenticação
api.interceptors.request.use(config => {
    const token = localStorage.getItem('@LEX:token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// Interceptor para tratar erros de autenticação
api.interceptors.response.use(
    response => {
        // Debug da resposta
        console.log('Resposta da requisição:', {
            status: response.status,
            data: response.data,
            url: response.config.url
        });
        return response;
    },
    error => {
        console.error('Erro na requisição:', {
            config: error.config,
            response: error.response,
            message: error.message,
            status: error.response ? error.response.status : null,
            data: error.response ? error.response.data : null
        });

        if (error.response && error.response.status === 401) {
            // Token inválido ou expirado
            localStorage.removeItem('@LEX:token');
            localStorage.removeItem('@LEX:user');
            window.location.href = '/login';
            return Promise.reject(new Error('Sessão expirada. Por favor, faça login novamente.'));
        }
        return Promise.reject(error);
    }
);

export const authService = {
    login: async(credentials) => {
        const response = await api.post('/auth/login', credentials);
        return response.data;
    },
    logout: async() => {
        await api.post('/auth/logout');
    },
};

export default api;