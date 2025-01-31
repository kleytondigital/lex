import { createContext, useContext, useState, useEffect } from 'react';
import { useDispatch } from 'react-redux';
import { setUser, logout as logoutAction } from '../store/slices/authSlice';
import api from '../services/api';

const AuthContext = createContext({});

export const AuthProvider = ({ children }) => {
    const [user, setLocalUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const dispatch = useDispatch();

    useEffect(() => {
        const loadStoredAuth = () => {
            const storedToken = localStorage.getItem('@LEX:token');
            const storedUser = localStorage.getItem('@LEX:user');

            if (storedToken && storedUser) {
                api.defaults.headers.authorization = `Bearer ${storedToken}`;
                const parsedUser = JSON.parse(storedUser);
                setLocalUser(parsedUser);
                dispatch(setUser(parsedUser));
            }

            setLoading(false);
        };

        loadStoredAuth();
    }, [dispatch]);

    const login = async(email, password) => {
        try {
            const response = await api.post('/auth/login', { email, password });
            const { user: userData, token } = response.data;

            api.defaults.headers.authorization = `Bearer ${token}`;
            localStorage.setItem('@LEX:token', token);
            localStorage.setItem('@LEX:user', JSON.stringify(userData));

            setLocalUser(userData);
            dispatch(setUser(userData));

            return userData.role === 'admin' ? '/admin' : '/';
        } catch (error) {
            const errorMessage = error.response && error.response.data && error.response.data.error;
            throw errorMessage || 'Erro ao fazer login';
        }
    };

    const logout = () => {
        localStorage.removeItem('@LEX:token');
        localStorage.removeItem('@LEX:user');
        api.defaults.headers.authorization = '';
        setLocalUser(null);
        dispatch(logoutAction());
    };

    return ( <
        AuthContext.Provider value = {
            {
                user,
                isAuthenticated: !!user,
                loading,
                login,
                logout,
            }
        } >
        { children } <
        /AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export default AuthProvider;