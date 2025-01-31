import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
    PlusIcon, 
    ArrowLeftIcon,
    PencilSquareIcon,
    TrashIcon,
    ArrowsUpDownIcon,
    VideoCameraIcon,
    DocumentTextIcon
} from '@heroicons/react/24/outline';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import ConfirmationModal from '../../components/ConfirmationModal';
import LoadingOverlay from '../../components/LoadingOverlay';

const ModuleLessons = () => {
    const { training_id, module_id } = useParams();
    const navigate = useNavigate();
    const [module, setModule] = useState(null);
    const [lessons, setLessons] = useState([]);
    const [loading, setLoading] = useState(true);
    const [isAddingLesson, setIsAddingLesson] = useState(false);
    const [deleteModal, setDeleteModal] = useState({ isOpen: false, lessonId: null });
    const [newLesson, setNewLesson] = useState({
        title: '',
        description: '',
        video_url: '',
        duration: '',
        content_type: 'video' // ou 'document'
    });

    useEffect(() => {
        fetchModuleData();
    }, [module_id]);

    const fetchModuleData = async () => {
        try {
            const [moduleRes, lessonsRes] = await Promise.all([
                api.get(`/admin/trainings/${training_id}/modules/${module_id}`),
                api.get(`/admin/trainings/${training_id}/modules/${module_id}/lessons`)
            ]);
            
            setModule(moduleRes.data);
            setLessons(lessonsRes.data);
        } catch (error) {
            console.error('Erro ao carregar dados:', error);
            toast.error('Erro ao carregar dados do módulo');
        } finally {
            setLoading(false);
        }
    };

    const handleAddLesson = async () => {
        try {
            setLoading(true);
            const response = await api.post(
                `/admin/trainings/${training_id}/modules/${module_id}/lessons`,
                newLesson
            );
            setLessons(prev => [...prev, response.data]);
            setNewLesson({
                title: '',
                description: '',
                video_url: '',
                duration: '',
                content_type: 'video'
            });
            setIsAddingLesson(false);
            toast.success('Aula adicionada com sucesso');
        } catch (error) {
            console.error('Erro ao adicionar aula:', error);
            toast.error('Erro ao adicionar aula');
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteLesson = async (lessonId) => {
        try {
            setLoading(true);
            await api.delete(`/admin/trainings/${training_id}/modules/${module_id}/lessons/${lessonId}`);
            setLessons(prev => prev.filter(l => l.id !== lessonId));
            setDeleteModal({ isOpen: false, lessonId: null });
            toast.success('Aula excluída com sucesso');
        } catch (error) {
            console.error('Erro ao excluir aula:', error);
            toast.error('Erro ao excluir aula');
        } finally {
            setLoading(false);
        }
    };

    const handleReorderLessons = async (lessonId, direction) => {
        const currentIndex = lessons.findIndex(l => l.id === lessonId);
        if (
            (direction === 'up' && currentIndex === 0) ||
            (direction === 'down' && currentIndex === lessons.length - 1)
        ) {
            return;
        }

        const newLessons = [...lessons];
        const targetIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
        [newLessons[currentIndex], newLessons[targetIndex]] = [newLessons[targetIndex], newLessons[currentIndex]];

        try {
            setLoading(true);
            await api.post(`/admin/trainings/${training_id}/modules/${module_id}/lessons/reorder`, {
                lessons: newLessons.map(l => l.id)
            });
            setLessons(newLessons);
        } catch (error) {
            console.error('Erro ao reordenar aulas:', error);
            toast.error('Erro ao reordenar aulas');
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return <LoadingOverlay message="Carregando..." />;
    }

    return (
        <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center">
                        <button
                            onClick={() => navigate(`/admin/trainings/config/${training_id}`)}
                            className="mr-4 text-gray-400 hover:text-gray-200"
                        >
                            <ArrowLeftIcon className="h-6 w-6" />
                        </button>
                        <div>
                            <h1 className="text-2xl font-semibold text-gray-200">
                                {module?.title}
                            </h1>
                            <p className="text-sm text-gray-400">
                                Gerenciamento de Aulas
                            </p>
                        </div>
                    </div>
                    <button
                        onClick={() => setIsAddingLesson(true)}
                        className="bg-orange-500 text-white px-4 py-2 rounded-lg hover:bg-orange-600 flex items-center focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                    >
                        <PlusIcon className="h-5 w-5 mr-2" />
                        Nova Aula
                    </button>
                </div>

                {/* Lista de Aulas */}
                <div className="bg-gray-900 rounded-lg shadow-lg border border-gray-800">
                    <div className="p-6">
                        <div className="space-y-4">
                            {lessons.map((lesson, index) => (
                                <div
                                    key={lesson.id}
                                    className="bg-gray-800 rounded-lg p-4 flex items-center justify-between"
                                >
                                    <div className="flex items-center flex-1">
                                        <div className="flex-shrink-0 mr-4">
                                            {lesson.content_type === 'video' ? (
                                                <VideoCameraIcon className="h-8 w-8 text-orange-500" />
                                            ) : (
                                                <DocumentTextIcon className="h-8 w-8 text-blue-500" />
                                            )}
                                        </div>
                                        <div>
                                            <h3 className="text-lg font-medium text-gray-200">
                                                {lesson.title}
                                            </h3>
                                            {lesson.description && (
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {lesson.description}
                                                </p>
                                            )}
                                            {lesson.duration && (
                                                <p className="text-sm text-gray-500 mt-1">
                                                    Duração: {lesson.duration}
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                    <div className="flex items-center space-x-2">
                                        <button
                                            onClick={() => handleReorderLessons(lesson.id, 'up')}
                                            disabled={index === 0}
                                            className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-50"
                                        >
                                            <ArrowsUpDownIcon className="h-5 w-5" />
                                        </button>
                                        <button
                                            onClick={() => navigate(`/admin/trainings/${training_id}/modules/${module_id}/lessons/${lesson.id}`)}
                                            className="p-1 text-orange-400 hover:text-orange-300"
                                        >
                                            <PencilSquareIcon className="h-5 w-5" />
                                        </button>
                                        <button
                                            onClick={() => setDeleteModal({ isOpen: true, lessonId: lesson.id })}
                                            className="p-1 text-red-400 hover:text-red-300"
                                        >
                                            <TrashIcon className="h-5 w-5" />
                                        </button>
                                    </div>
                                </div>
                            ))}

                            {lessons.length === 0 && (
                                <div className="text-center py-12">
                                    <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-600" />
                                    <h3 className="mt-2 text-lg font-medium text-gray-300">
                                        Nenhuma aula cadastrada
                                    </h3>
                                    <p className="mt-1 text-sm text-gray-500">
                                        Comece adicionando sua primeira aula.
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Modal de Adicionar Aula */}
                        {isAddingLesson && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
                                <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
                                    <h3 className="text-lg font-medium text-gray-200 mb-4">
                                        Nova Aula
                                    </h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                                Título
                                            </label>
                                            <input
                                                type="text"
                                                value={newLesson.title}
                                                onChange={(e) => setNewLesson(prev => ({ ...prev, title: e.target.value }))}
                                                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                                placeholder="Digite o título da aula"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                                Descrição
                                            </label>
                                            <textarea
                                                value={newLesson.description}
                                                onChange={(e) => setNewLesson(prev => ({ ...prev, description: e.target.value }))}
                                                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                                placeholder="Digite a descrição da aula"
                                                rows="3"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                                Tipo de Conteúdo
                                            </label>
                                            <select
                                                value={newLesson.content_type}
                                                onChange={(e) => setNewLesson(prev => ({ ...prev, content_type: e.target.value }))}
                                                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                            >
                                                <option value="video">Vídeo</option>
                                                <option value="document">Documento</option>
                                            </select>
                                        </div>
                                        {newLesson.content_type === 'video' && (
                                            <>
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                                        URL do Vídeo
                                                    </label>
                                                    <input
                                                        type="text"
                                                        value={newLesson.video_url}
                                                        onChange={(e) => setNewLesson(prev => ({ ...prev, video_url: e.target.value }))}
                                                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                                        placeholder="Cole a URL do vídeo"
                                                    />
                                                </div>
                                                <div>
                                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                                        Duração
                                                    </label>
                                                    <input
                                                        type="text"
                                                        value={newLesson.duration}
                                                        onChange={(e) => setNewLesson(prev => ({ ...prev, duration: e.target.value }))}
                                                        className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                                        placeholder="Ex: 10:30"
                                                    />
                                                </div>
                                            </>
                                        )}
                                        <div className="flex justify-end space-x-3">
                                            <button
                                                onClick={() => setIsAddingLesson(false)}
                                                className="px-4 py-2 text-gray-400 hover:text-gray-200"
                                            >
                                                Cancelar
                                            </button>
                                            <button
                                                onClick={handleAddLesson}
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

            {/* Modal de Confirmação de Exclusão */}
            <ConfirmationModal
                isOpen={deleteModal.isOpen}
                onClose={() => setDeleteModal({ isOpen: false, lessonId: null })}
                onConfirm={() => handleDeleteLesson(deleteModal.lessonId)}
                title="Excluir Aula"
                message="Tem certeza que deseja excluir esta aula? Esta ação não pode ser desfeita."
                confirmText="Excluir"
                cancelText="Cancelar"
                type="danger"
            />
        </div>
    );
};

export default ModuleLessons; 