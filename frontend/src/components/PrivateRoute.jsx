import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const PrivateRoute = ({ children }) => {
    const { user, loading } = useAuth();

    if (loading) {
        return (
            <div className="flex justify-center items-center h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    if (!user) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white">
                <h1 className="text-4xl font-bold mb-4">Acesso Restrito</h1>
                <p className="text-gray-400 mb-8">
                    Você precisa estar logado para acessar esta página.
                </p>
                <a 
                    href="/login" 
                    className="px-6 py-3 bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-colors"
                >
                    Fazer Login
                </a>
            </div>
        );
    }

    return children;
};

export default PrivateRoute; 