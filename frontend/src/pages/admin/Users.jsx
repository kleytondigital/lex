import { useState, useEffect } from 'react';
import { 
    MagnifyingGlassIcon,
    PencilSquareIcon,
    TrashIcon,
    UserPlusIcon
} from '@heroicons/react/24/outline';
import api from '../../services/api';
import { toast } from 'react-hot-toast';

const AdminUsers = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      console.log('Iniciando busca de usuários...');
      const response = await api.get('/admin/users');
      console.log('Resposta da busca de usuários:', response.data);
      
      // Verificar se a resposta contém a propriedade users
      const userData = response.data?.users || [];
      console.log('Dados processados:', userData);
      
      setUsers(userData);
      setError(null);
      
      if (userData.length === 0) {
        toast.error('Nenhum usuário encontrado');
      }
    } catch (error) {
      console.error('Erro ao carregar usuários:', error);
      const errorMessage = error.response?.data?.message || 'Erro ao carregar usuários. Por favor, tente novamente.';
      setError(errorMessage);
      toast.error(errorMessage);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  // Só filtrar se users for um array
  const filteredUsers = Array.isArray(users) ? users.filter(user => {
    const matchesSearch = (
      user.name?.toLowerCase().includes(search.toLowerCase()) ||
      user.email?.toLowerCase().includes(search.toLowerCase())
    );
    
    if (filter === 'all') return matchesSearch;
    if (filter === 'active') return matchesSearch && user.status === 'active';
    if (filter === 'inactive') return matchesSearch && user.status === 'inactive';
    return matchesSearch;
  }) : [];

  const handleStatusChange = async (userId, newStatus) => {
    try {
      await api.patch(`/admin/users/${userId}/status`, { status: newStatus });
      setUsers(prevUsers => 
        prevUsers.map(user => 
          user.id === userId ? { ...user, status: newStatus } : user
        )
      );
      toast.success(`Status do usuário alterado para ${newStatus}`);
    } catch (error) {
      console.error('Erro ao atualizar status:', error);
      const errorMessage = error.response?.data?.message || 'Erro ao atualizar status do usuário';
      toast.error(errorMessage);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-gray-500">Carregando usuários...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <div className="text-red-500">{error}</div>
        <button 
          onClick={fetchUsers}
          className="px-4 py-2 bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-colors"
        >
          Tentar Novamente
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex flex-col sm:flex-row justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-200 mb-4 sm:mb-0">
          Gerenciar Usuários
        </h1>
        
        <div className="flex space-x-4 w-full sm:w-auto">
          <div className="relative flex-1 sm:flex-initial">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Buscar usuários..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 pr-4 py-2 w-full border border-gray-700 bg-gray-800 text-gray-200 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
            />
          </div>
          
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-4 py-2 border border-gray-700 bg-gray-800 text-gray-200 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
          >
            <option value="all">Todos</option>
            <option value="active">Ativos</option>
            <option value="inactive">Inativos</option>
          </select>
        </div>
      </div>

      {filteredUsers.length === 0 ? (
        <div className="text-center py-8 text-gray-400">
          Nenhum usuário encontrado
        </div>
      ) : (
        <div className="bg-gray-800 shadow overflow-hidden sm:rounded-lg border border-gray-700">
          <table className="min-w-full divide-y divide-gray-700">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Usuário
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Cursos
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Membro desde
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Ações
                </th>
              </tr>
            </thead>
            <tbody className="bg-gray-800 divide-y divide-gray-700">
              {filteredUsers.map((user) => (
                <tr key={user.id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="flex-shrink-0 h-10 w-10">
                        <img
                          className="h-10 w-10 rounded-full"
                          src={user.avatar || '/default-avatar.png'}
                          alt={user.name}
                        />
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-gray-200">
                          {user.name}
                        </div>
                        <div className="text-sm text-gray-400">
                          {user.email}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`
                      px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                      ${user.status === 'active'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-red-100 text-red-800'
                      }
                    `}>
                      {user.status === 'active' ? 'Ativo' : 'Inativo'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {user.enrolledCourses || 0} cursos
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleStatusChange(
                        user.id,
                        user.status === 'active' ? 'inactive' : 'active'
                      )}
                      className={`
                        text-sm font-medium px-3 py-1 rounded-md
                        ${user.status === 'active'
                          ? 'text-red-400 hover:text-red-300'
                          : 'text-green-400 hover:text-green-300'
                        }
                      `}
                    >
                      {user.status === 'active' ? 'Desativar' : 'Ativar'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default AdminUsers; 