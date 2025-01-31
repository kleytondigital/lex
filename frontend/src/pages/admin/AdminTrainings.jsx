import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
    PlusIcon, 
    PencilSquareIcon, 
    TrashIcon, 
    MagnifyingGlassIcon,
    EyeIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import api from '../../services/api';
import LoadingOverlay from '../../components/LoadingOverlay';
import ConfirmationModal from '../../components/ConfirmationModal';

const AdminTrainings = () => {
    const navigate = useNavigate();
    const [trainings, setTrainings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [deleteModal, setDeleteModal] = useState({ isOpen: false, trainingId: null });
    const [searchQuery, setSearchQuery] = useState('');
    const [statusFilter, setStatusFilter] = useState('Todos');

    useEffect(() => {
        fetchTrainings();
    }, []);

    const fetchTrainings = async () => {
        try {
            const response = await api.get('/admin/trainings');
            setTrainings(response.data);
        } catch (error) {
            console.error('Erro ao carregar treinamentos:', error);
            toast.error('Erro ao carregar treinamentos');
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id) => {
        try {
            await api.delete(`/admin/trainings/${id}`);
            toast.success('Treinamento excluído com sucesso');
            fetchTrainings();
        } catch (error) {
            console.error('Erro ao excluir treinamento:', error);
            toast.error('Erro ao excluir treinamento');
        }
        setDeleteModal({ isOpen: false, trainingId: null });
    };

    const handlePublish = async (id, currentStatus) => {
        try {
            await api.patch(`/admin/trainings/${id}/status`, {
                status: currentStatus === 'published' ? 'draft' : 'published'
            });
            toast.success(currentStatus === 'published' ? 'Treinamento despublicado' : 'Treinamento publicado');
            fetchTrainings();
        } catch (error) {
            console.error('Erro ao alterar status do treinamento:', error);
            toast.error('Erro ao alterar status do treinamento');
        }
    };

    const filteredTrainings = trainings.filter(training => {
        const matchesSearch = training.name.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesStatus = statusFilter === 'Todos' || 
            (statusFilter === 'Publicado' && training.status === 'published') ||
            (statusFilter === 'Rascunho' && training.status === 'draft');
        return matchesSearch && matchesStatus;
    });

    if (loading) {
        return <LoadingOverlay message="Carregando treinamentos..." />;
    }

    return (
        <div className="p-8">
            <div className="flex justify-between items-center mb-8">
                <h1 className="text-2xl font-semibold text-white">Gerenciamento de Treinamentos</h1>
                <button
                    onClick={() => navigate('/admin/trainings/create')}
                    className="flex items-center gap-2 bg-orange-500 hover:bg-orange-600 text-white px-4 py-2 rounded-lg transition-colors"
                >
                    <PlusIcon className="h-5 w-5" />
                    Novo Treinamento
                </button>
            </div>

            <div className="bg-gray-900 rounded-lg p-6">
                <div className="flex gap-4 mb-6">
                    <div className="flex-1 relative">
                        <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                        <input
                            type="text"
                            placeholder="Buscar treinamentos..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-gray-800 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-orange-500"
                        />
                    </div>
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="bg-gray-800 text-white px-4 py-2 rounded-lg border border-gray-700 focus:outline-none focus:border-orange-500"
                    >
                        <option>Todos</option>
                        <option>Publicado</option>
                        <option>Rascunho</option>
                    </select>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="text-left border-b border-gray-800">
                                <th className="pb-3 text-gray-400 font-medium">TREINAMENTO</th>
                                <th className="pb-3 text-gray-400 font-medium">CATEGORIA</th>
                                <th className="pb-3 text-gray-400 font-medium">STATUS</th>
                                <th className="pb-3 text-gray-400 font-medium">PREÇO</th>
                                <th className="pb-3 text-gray-400 font-medium text-right">AÇÕES</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredTrainings.map((training) => (
                                <tr key={training.id} className="border-b border-gray-800">
                                    <td className="py-4">
                                        <div className="flex items-center gap-3">
                                            <img
                                                src={training.thumbnail || '/placeholder-training.png'}
                                                alt=""
                                                className="h-10 w-10 rounded object-cover"
                                            />
                                            <span className="text-white font-medium">{training.name}</span>
                                        </div>
                                    </td>
                                    <td className="py-4 text-gray-300">
                                        {training.category || 'Iniciante'}
                                    </td>
                                    <td className="py-4">
                                        <span className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${
                                            training.status === 'published'
                                                ? 'bg-green-400/10 text-green-400'
                                                : 'bg-yellow-400/10 text-yellow-400'
                                        }`}>
                                            {training.status === 'published' ? 'Publicado' : 'Rascunho'}
                                        </span>
                                    </td>
                                    <td className="py-4 text-gray-300">
                                        {training.price ? `R$ ${training.price}` : 'Gratuito'}
                                    </td>
                                    <td className="py-4">
                                        <div className="flex justify-end gap-3">
                                            <button
                                                onClick={() => handlePublish(training.id, training.status)}
                                                className="text-blue-400 hover:text-blue-300"
                                                title={training.status === 'published' ? 'Despublicar' : 'Publicar'}
                                            >
                                                <EyeIcon className="h-5 w-5" />c
                                            </button>
                                            <button
                                                onClick={() => navigate(`/admin/trainings/config/${training.id}`)}
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
            </div>

            <ConfirmationModal
                isOpen={deleteModal.isOpen}
                onClose={() => setDeleteModal({ isOpen: false, trainingId: null })}
                onConfirm={() => handleDelete(deleteModal.trainingId)}
                title="Excluir Treinamento"
                message="Tem certeza que deseja excluir este treinamento? Esta ação não pode ser desfeita."
                confirmText="Excluir"
                cancelText="Cancelar"
                type="danger"
            />
        </div>
    );
};

export default AdminTrainings; 