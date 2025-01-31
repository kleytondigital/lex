import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeftIcon } from '@heroicons/react/24/outline';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';

const LessonConfig = () => {
    const { training_id, module_id, lesson_id } = useParams();
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [lesson, setLesson] = useState({
        title: '',
        description: '',
        content_type: 'video',
        video_url: '',
        duration: ''
    });

    useEffect(() => {
        fetchLessonData();
    }, [lesson_id]);

    const fetchLessonData = async () => {
        try {
            const response = await api.get(`/admin/trainings/${training_id}/modules/${module_id}/lessons/${lesson_id}`);
            setLesson(response.data);
        } catch (error) {
            console.error('Erro ao carregar dados da aula:', error);
            toast.error('Erro ao carregar dados da aula');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setSaving(true);

        try {
            await api.put(`/admin/trainings/${training_id}/modules/${module_id}/lessons/${lesson_id}`, lesson);
            toast.success('Aula atualizada com sucesso');
            navigate(`/admin/trainings/${training_id}/modules/${module_id}/lessons`);
        } catch (error) {
            console.error('Erro ao atualizar aula:', error);
            toast.error('Erro ao atualizar aula');
        } finally {
            setSaving(false);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setLesson(prev => ({
            ...prev,
            [name]: value
        }));
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
                            onClick={() => navigate(`/admin/trainings/${training_id}/modules/${module_id}/lessons`)}
                            className="mr-4 text-gray-400 hover:text-gray-200"
                        >
                            <ArrowLeftIcon className="h-6 w-6" />
                        </button>
                        <div>
                            <h1 className="text-2xl font-semibold text-gray-200">
                                Configuração da Aula
                            </h1>
                            <p className="text-sm text-gray-400">
                                Edite as informações da aula
                            </p>
                        </div>
                    </div>
                </div>

                {/* Formulário */}
                <div className="bg-gray-900 rounded-lg shadow-lg border border-gray-800">
                    <form onSubmit={handleSubmit} className="p-6 space-y-6">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                Título
                            </label>
                            <input
                                type="text"
                                name="title"
                                value={lesson.title}
                                onChange={handleChange}
                                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                required
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                Descrição
                            </label>
                            <textarea
                                name="description"
                                value={lesson.description || ''}
                                onChange={handleChange}
                                rows="4"
                                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-1">
                                Tipo de Conteúdo
                            </label>
                            <select
                                name="content_type"
                                value={lesson.content_type}
                                onChange={handleChange}
                                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                            >
                                <option value="video">Vídeo</option>
                                <option value="document">Documento</option>
                            </select>
                        </div>

                        {lesson.content_type === 'video' && (
                            <>
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                        URL do Vídeo
                                    </label>
                                    <input
                                        type="url"
                                        name="video_url"
                                        value={lesson.video_url || ''}
                                        onChange={handleChange}
                                        className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-1">
                                        Duração
                                    </label>
                                    <input
                                        type="text"
                                        name="duration"
                                        value={lesson.duration || ''}
                                        onChange={handleChange}
                                        placeholder="Ex: 10:30"
                                        className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                    />
                                </div>
                            </>
                        )}

                        <div className="flex justify-end space-x-3 pt-6">
                            <button
                                type="button"
                                onClick={() => navigate(`/admin/trainings/${training_id}/modules/${module_id}/lessons`)}
                                className="px-4 py-2 text-gray-400 hover:text-gray-200"
                            >
                                Cancelar
                            </button>
                            <button
                                type="submit"
                                disabled={saving}
                                className="px-4 py-2 bg-orange-500 text-white rounded-lg hover:bg-orange-600 disabled:opacity-50"
                            >
                                {saving ? 'Salvando...' : 'Salvar Alterações'}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default LessonConfig; 