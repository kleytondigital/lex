import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
    PlusIcon, 
    ArrowLeftIcon,
    PencilSquareIcon,
    TrashIcon,
    ArrowsUpDownIcon
} from '@heroicons/react/24/outline';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';
import { Switch } from '@headlessui/react';

const TrainingConfig = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [training, setTraining] = useState(null);
    const [modules, setModules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [isAddingModule, setIsAddingModule] = useState(false);
    const [newModule, setNewModule] = useState({ title: '', description: '' });
    const [isPublished, setIsPublished] = useState(false);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        fetchTrainingData();
    }, [id]);

    const fetchTrainingData = async () => {
        try {
            const [trainingRes, modulesRes] = await Promise.all([
                api.get(`/admin/trainings/${id}`),
                api.get(`/admin/trainings/${id}/modules`)
            ]);
            
            setTraining(trainingRes.data);
            setModules(modulesRes.data);
            setIsPublished(trainingRes.data.status === 'published');
        } catch (error) {
            console.error('Erro ao carregar dados:', error);
            toast.error('Erro ao carregar dados do treinamento');
            navigate('/admin/trainings');
        } finally {
            setLoading(false);
        }
    };

    const handleAddModule = async () => {
        try {
            setIsAddingModule(true);
            const response = await api.post(`/admin/trainings/${id}/modules`, newModule);
            setModules(prev => [...prev, response.data]);
            setNewModule({ title: '', description: '' });
            toast.success('Módulo adicionado com sucesso');
        } catch (error) {
            console.error('Erro ao adicionar módulo:', error);
            toast.error('Erro ao adicionar módulo');
        } finally {
            setIsAddingModule(false);
        }
    };

    const handleDeleteModule = async (moduleId) => {
        if (!window.confirm('Tem certeza que deseja excluir este módulo?')) {
            return;
        }

        try {
            await api.delete(`/admin/trainings/${id}/modules/${moduleId}`);
            setModules(prev => prev.filter(m => m.id !== moduleId));
            toast.success('Módulo excluído com sucesso');
        } catch (error) {
            console.error('Erro ao excluir módulo:', error);
            toast.error('Erro ao excluir módulo');
        }
    };

    const handleReorderModules = async (moduleId, direction) => {
        const currentIndex = modules.findIndex(m => m.id === moduleId);
        if (
            (direction === 'up' && currentIndex === 0) ||
            (direction === 'down' && currentIndex === modules.length - 1)
        ) {
            return;
        }

        const newModules = [...modules];
        const targetIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
        [newModules[currentIndex], newModules[targetIndex]] = [newModules[targetIndex], newModules[currentIndex]];

        try {
            await api.post(`/admin/trainings/${id}/modules/reorder`, {
                modules: newModules.map(m => m.id)
            });
            setModules(newModules);
        } catch (error) {
            console.error('Erro ao reordenar módulos:', error);
            toast.error('Erro ao reordenar módulos');
        }
    };

    const handlePublishToggle = async () => {
        try {
            setSaving(true);
            await api.patch(`/admin/trainings/${id}/status`, {
                status: !isPublished ? 'published' : 'draft'
            });
            setIsPublished(!isPublished);
            toast.success(
                !isPublished 
                    ? 'Treinamento publicado com sucesso!' 
                    : 'Treinamento despublicado com sucesso!'
            );
        } catch (error) {
            console.error('Erro ao alterar status do treinamento:', error);
            toast.error('Erro ao alterar status do treinamento');
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return <LoadingOverlay message="Carregando treinamento..." />;
    }

    return (
        <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center">
                        <button
                            onClick={() => navigate('/admin/trainings')}
                            className="mr-4 text-gray-400 hover:text-gray-200"
                        >
                            <ArrowLeftIcon className="h-6 w-6" />
                        </button>
                        <div>
                            <h1 className="text-2xl font-semibold text-gray-200">
                                {training?.name}
                            </h1>
                            <p className="text-sm text-gray-400">
                                Configurações do treinamento
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-3">
                            <span className="text-gray-400">
                                {isPublished ? 'Publicado' : 'Rascunho'}
                            </span>
                            <Switch
                                checked={isPublished}
                                onChange={handlePublishToggle}
                                disabled={saving}
                                className={`${
                                    isPublished ? 'bg-orange-500' : 'bg-gray-700'
                                } relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 focus:ring-offset-gray-900`}
                            >
                                <span
                                    className={`${
                                        isPublished ? 'translate-x-6' : 'translate-x-1'
                                    } inline-block h-4 w-4 transform rounded-full bg-white transition-transform`}
                                />
                            </Switch>
                        </div>
                        <button
                            onClick={() => navigate(`/admin/trainings/${id}/modules`)}
                            className="px-4 py-2 bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-colors"
                        >
                            Gerenciar Módulos
                        </button>
                    </div>
                </div>

                {/* Módulos */}
                <div className="bg-gray-900 rounded-lg shadow-lg border border-gray-800">
                    <div className="p-6">
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-xl font-medium text-gray-200">Módulos</h2>
                            <button
                                onClick={() => setIsAddingModule(true)}
                                className="bg-orange-500 text-white px-4 py-2 rounded-lg hover:bg-orange-600 flex items-center focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                            >
                                <PlusIcon className="h-5 w-5 mr-2" />
                                Novo Módulo
                            </button>
                        </div>

                        {/* Lista de Módulos */}
                        <div className="space-y-4">
                            {modules.map((module, index) => (
                                <div
                                    key={module.id}
                                    className="bg-gray-800 rounded-lg p-4 flex items-center justify-between"
                                >
                                    <div className="flex-1">
                                        <h3 className="text-lg font-medium text-gray-200">
                                            {module.title}
                                        </h3>
                                        {module.description && (
                                            <p className="text-sm text-gray-400 mt-1">
                                                {module.description}
                                            </p>
                                        )}
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <button
                                            onClick={() => handleReorderModules(module.id, 'up')}
                                            disabled={index === 0}
                                            className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-50"
                                        >
                                            <ArrowsUpDownIcon className="h-5 w-5" />
                                        </button>
                                        <button
                                            onClick={() => navigate(`/admin/trainings/${id}/modules/${module.id}/lessons`)}
                                            className="p-1 text-orange-400 hover:text-orange-300"
                                        >
                                            <PencilSquareIcon className="h-5 w-5" />
                                        </button>
                                        <button
                                            onClick={() => handleDeleteModule(module.id)}
                                            className="p-1 text-red-400 hover:text-red-300"
                                        >
                                            <TrashIcon className="h-5 w-5" />
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Modal de Adicionar Módulo */}
                        {isAddingModule && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
                                <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
                                    <h3 className="text-lg font-medium text-gray-200 mb-4">
                                        Novo Módulo
                                    </h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                                Título
                                            </label>
                                            <input
                                                type="text"
                                                value={newModule.title}
                                                onChange={(e) => setNewModule(prev => ({ ...prev, title: e.target.value }))}
                                                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                                placeholder="Digite o título do módulo"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                                Descrição
                                            </label>
                                            <textarea
                                                value={newModule.description}
                                                onChange={(e) => setNewModule(prev => ({ ...prev, description: e.target.value }))}
                                                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                                placeholder="Digite a descrição do módulo"
                                                rows="3"
                                            />
                                        </div>
                                        <div className="flex justify-end space-x-3">
                                            <button
                                                onClick={() => setIsAddingModule(false)}
                                                className="px-4 py-2 text-gray-400 hover:text-gray-200"
                                            >
                                                Cancelar
                                            </button>
                                            <button
                                                onClick={handleAddModule}
                                                className="px-4 py-2 bg-orange-500 text-white rounded-lg hover:bg-orange-600"
                                            >
                                                Adicionar
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TrainingConfig; 