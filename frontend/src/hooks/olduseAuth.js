import { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext();

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const token = localStorage.getItem('token');
        const savedUser = localStorage.getItem('user');

        if (token && savedUser) {
            setUser(JSON.parse(savedUser));
            api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        }

        setLoading(false);
    }, []);

    const login = async(email, password) => {
        try {
            const response = await api.post('/auth/login', { email, password });
            const { token, user } = response.data;

            localStorage.setItem('token', token);
            localStorage.setItem('user', JSON.stringify(user));
            api.defaults.headers.common['Authorization'] = `Bearer ${token}`;

            setUser(user);
            return user.role === 'admin' ? '/admin' : '/dashboard';
        } catch (error) {
            throw error.response && error.response.data && error.response.data.error || 'Erro ao fazer login';
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        delete api.defaults.headers.common['Authorization'];
        setUser(null);
    };

    return ( <
        AuthContext.Provider value = {
            { user, login, logout, loading } } > { children } <
        /AuthContext.Provider>
    );
}

export function useAuth() {
    return useContext(AuthContext);
}