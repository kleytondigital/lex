import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
    PlusIcon, 
    MagnifyingGlassIcon, 
    PencilSquareIcon, 
    TrashIcon, 
    EyeIcon,
    AcademicCapIcon,
    ChevronLeftIcon,
    ChevronRightIcon
} from '@heroicons/react/24/outline';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import ConfirmationModal from '../../components/ConfirmationModal';
import LoadingOverlay from '../../components/LoadingOverlay';

const AdminTrainings = () => {
    const navigate = useNavigate();
    const [trainings, setTrainings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState('');
    const [filter, setFilter] = useState('all');
    const [pagination, setPagination] = useState({
        page: 1,
        limit: 10,
        totalItems: 0,
        totalPages: 0
    });
    const [isCreating, setIsCreating] = useState(false);
    const [deleteModal, setDeleteModal] = useState({ isOpen: false, trainingId: null });

    useEffect(() => {
        fetchTrainings();
    }, [pagination.page, search]); // Refetch quando mudar a página ou a busca

    const fetchTrainings = async () => {
        try {
            const response = await api.get('/admin/trainings', {
                params: {
                    page: pagination.page,
                    limit: pagination.limit,
                    search: search
                }
            });
            
            // Atualiza os dados e a paginação
            setTrainings(response.data.trainings);
            setPagination(prev => ({
                ...prev,
                totalItems: response.data.pagination.totalItems,
                totalPages: response.data.pagination.totalPages
            }));
        } catch (error) {
            console.error('Erro ao carregar treinamentos:', error);
            toast.error('Erro ao carregar treinamentos');
        } finally {
            setLoading(false);
        }
    };

    const handleStatusChange = async (trainingId, newStatus) => {
        try {
            await api.patch(`/admin/trainings/${trainingId}/status`, { status: newStatus });
            toast.success('Status do treinamento atualizado com sucesso');
            fetchTrainings();
            setDeleteModal({ isOpen: false, trainingId: null });
        } catch (error) {
            console.error('Erro ao atualizar status:', error);
            toast.error('Erro ao atualizar status do treinamento');
        }
    };

    const handlePageChange = (newPage) => {
        setPagination(prev => ({ ...prev, page: newPage }));
    };

    const handleCreateTraining = async (data) => {
        setIsCreating(true);
        try {
            const response = await api.post('/admin/trainings', data);
            toast.success('Treinamento criado com sucesso');
            navigate(`/admin/trainings/config/${response.data.id}`);
        } catch (error) {
            console.error('Erro ao criar treinamento:', error);
            toast.error('Erro ao criar treinamento');
        } finally {
            setIsCreating(false);
        }
    };

    // Filtra os treinamentos com base no status
    const filteredTrainings = trainings?.filter(training => {
        if (filter === 'all') return true;
        return training.status === filter;
    }) || [];

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    if (trainings?.length === 0 && !search && filter === 'all') {
        return (
            <div className="py-6">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                    <div className="flex justify-between items-center mb-6">
                        <h1 className="text-2xl font-semibold text-gray-200">Gerenciamento de Treinamentos</h1>
                    </div>
                    <div className="bg-gray-900 rounded-lg shadow-lg p-6 border border-gray-800">
                        <div className="text-center py-12">
                            <AcademicCapIcon className="mx-auto h-12 w-12 text-gray-600" />
                            <h3 className="mt-2 text-lg font-medium text-gray-300">Nenhum treinamento criado</h3>
                            <p className="mt-1 text-sm text-gray-500">Comece criando seu primeiro treinamento.</p>
                            <div className="mt-6">
                                <button
                                    onClick={() => navigate('/admin/trainings/create')}
                                    className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-orange-500 hover:bg-orange-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                                >
                                    <PlusIcon className="-ml-1 mr-2 h-5 w-5" aria-hidden="true" />
                                    Criar Treinamento
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <>
            {isCreating && <LoadingOverlay message="Criando treinamento..." />}
            
            <ConfirmationModal
                isOpen={deleteModal.isOpen}
                onClose={() => setDeleteModal({ isOpen: false, trainingId: null })}
                onConfirm={() => handleStatusChange(deleteModal.trainingId, 'deleted')}
                title="Excluir Treinamento"
                message="Tem certeza que deseja excluir este treinamento? Esta ação não pode ser desfeita."
                confirmText="Excluir"
                cancelText="Cancelar"
                type="danger"
            />

        <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                <div className="flex justify-between items-center mb-6">
                    <h1 className="text-2xl font-semibold text-gray-200">Gerenciamento de Treinamentos</h1>
                    <button
                        className="bg-orange-500 text-white px-4 py-2 rounded-lg hover:bg-orange-600 flex items-center focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                        onClick={() => navigate('/admin/trainings/create')}
                    >
                        <PlusIcon className="h-5 w-5 mr-2" />
                        Novo Treinamento
                    </button>
                </div>

                <div className="bg-gray-900 rounded-lg shadow-lg border border-gray-800">
                    <div className="p-6">
                        <div className="flex flex-col sm:flex-row justify-between items-center mb-4 space-y-3 sm:space-y-0">
                            <div className="flex items-center space-x-4 w-full sm:w-auto">
                                <div className="relative flex-1 sm:flex-none">
                                    <input
                                        type="text"
                                        placeholder="Buscar treinamentos..."
                                        value={search}
                                        onChange={(e) => setSearch(e.target.value)}
                                        className="pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg w-full sm:w-64 text-gray-300 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                                    />
                                    <MagnifyingGlassIcon className="h-5 w-5 text-gray-500 absolute left-3 top-2.5" />
                                </div>
                                <select
                                    value={filter}
                                    onChange={(e) => setFilter(e.target.value)}
                                    className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-300 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                                >
                                    <option value="all">Todos</option>
                                    <option value="draft">Rascunho</option>
                                    <option value="published">Publicado</option>
                                </select>
                            </div>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-800">
                                <thead>
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                            Treinamento
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                            Categoria
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                            Status
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                            Preço
                                        </th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                                            Ações
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="bg-gray-900 divide-y divide-gray-800">
                                    {filteredTrainings.map((training) => (
                                        <tr key={training.id}>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="flex items-center">
                                                    <div className="flex-shrink-0 h-10 w-10">
                                                        <img
                                                            className="h-10 w-10 rounded-lg object-cover"
                                                            src={training.thumbnail || '/placeholder-training.png'}
                                                            alt={training.name}
                                                        />
                                                    </div>
                                                    <div className="ml-4">
                                                        <div className="text-sm font-medium text-gray-200">
                                                            {training.name}
                                                        </div>
                                                        <div className="text-sm text-gray-500">
                                                            {training.duration}
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="text-sm text-gray-300">{training.category || 'Iniciante'}</div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${
                                                    training.status === 'published'
                                                            ? 'bg-green-400/10 text-green-400'
                                                            : 'bg-yellow-400/10 text-yellow-400'
                                                }`}>
                                                    {training.status === 'published' ? 'Publicado' : 'Rascunho'}
                                                </span>
                                            </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="text-sm text-gray-300">
                                                        {training.price ? `R$ ${training.price}` : 'Gratuito'}
                                                    </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                <div className="flex justify-end space-x-2">
                                                    <button
                                                        onClick={() => navigate(`/admin/trainings/config/${training.id}`)}
                                                            className="text-orange-400 hover:text-orange-300"
                                                            title="Visualizar"
                                                    >
                                                        <EyeIcon className="h-5 w-5" />
                                                    </button>
                                                    <button
                                                        onClick={() => navigate(`/admin/trainings/edit/${training.id}`)}
                                                            className="text-blue-400 hover:text-blue-300"
                                                            title="Editar"
                                                    >
                                                        <PencilSquareIcon className="h-5 w-5" />
                                                    </button>
                                                    <button
                                                            onClick={() => setDeleteModal({ isOpen: true, trainingId: training.id })}
                                                        className="text-red-400 hover:text-red-300"
                                                            title="Excluir"
                                                    >
                                                        <TrashIcon className="h-5 w-5" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Paginação */}
                            <div className="flex justify-between items-center mt-4">
                                <div className="text-sm text-gray-500">
                                    Mostrando {((pagination.page - 1) * pagination.limit) + 1} a {Math.min(pagination.page * pagination.limit, pagination.totalItems)} de {pagination.totalItems} resultados
                                </div>
                                <div className="flex space-x-2">
                                <button
                                    onClick={() => handlePageChange(pagination.page - 1)}
                                    disabled={pagination.page === 1}
                                        className="px-3 py-1 rounded bg-gray-800 text-gray-300 disabled:opacity-50"
                                >
                                        <ChevronLeftIcon className="h-5 w-5" />
                                </button>
                                <button
                                    onClick={() => handlePageChange(pagination.page + 1)}
                                    disabled={pagination.page === pagination.totalPages}
                                        className="px-3 py-1 rounded bg-gray-800 text-gray-300 disabled:opacity-50"
                                >
                                        <ChevronRightIcon className="h-5 w-5" />
                                </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}

export default AdminTrainings; 