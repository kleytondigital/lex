import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const RootRedirect = () => {
    const { user, loading } = useAuth();

    if (loading) {
        return (
            <div className="flex justify-center items-center h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    // Se houver um usuário autenticado, redireciona para a rota apropriada
    if (user) {
        if (user.role === 'admin') {
            return <Navigate to="/admin" replace />;
        }
        return <Navigate to="/dashboard" replace />;
    }

    // Se não houver usuário, mostra página não encontrada
    return (
        <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white">
            <h1 className="text-4xl font-bold mb-4">Página não encontrada</h1>
            <p className="text-gray-400">
                A página que você está procurando não existe ou não está disponível.
            </p>
        </div>
    );
};

export default RootRedirect; 