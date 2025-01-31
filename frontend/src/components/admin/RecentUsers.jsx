import { useState, useEffect } from 'react';
import api from '../../services/api';
import { 
    UsersIcon,
    ArrowRightIcon
} from '@heroicons/react/24/outline';

const RecentUsers = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await api.get('/admin/users?limit=5');
                // Ensure response.data is an array
                const userData = Array.isArray(response.data) ? response.data : [];
                setUsers(userData);
                setError(null);
            } catch (error) {
                console.error('Erro ao buscar usuários:', error);
                setError('Erro ao carregar usuários');
                setUsers([]);
            } finally {
                setLoading(false);
            }
        };

        fetchUsers();
    }, []);

    if (loading) return <div>Carregando...</div>;
    if (error) return <div className="text-red-500">{error}</div>;
    if (users.length === 0) return <div>Nenhum usuário encontrado</div>;

    return (
        <div className="bg-[#1a1a1a] rounded-lg shadow-lg p-6">
            <div className="px-4 py-5 sm:px-6">
                <h3 className="text-lg leading-6 font-medium text-gray-300">
                    Usuários Recentes
                </h3>
            </div>
            <div className="border-t border-gray-700">
                <ul className="divide-y divide-gray-700">
                    {users.map((user) => (
                        <li key={user.id} className="px-4 py-4 sm:px-6">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center">
                                    <div className="flex-shrink-0">
                                        <img
                                            className="h-8 w-8 rounded-full"
                                            src={user.avatar || '/default-avatar.png'}
                                            alt=""
                                        />
                                    </div>
                                    <div className="ml-3">
                                        <p className="text-sm font-medium text-gray-500">{user.name}</p>
                                        <p className="text-sm text-gray-600">{user.email}</p>
                                    </div>
                                </div>
                                <div className="ml-3">
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                        user.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                                    }`}>
                                        {user.status}
                                    </span>
                                </div>
                            </div>
                        </li>
                    ))}
                </ul>
            </div>
            <div className="users-section">
                <UsersIcon className="h-6 w-6" />
                <ArrowRightIcon className="h-5 w-5" />
            </div>
        </div>
    );
};

export default RecentUsers; 