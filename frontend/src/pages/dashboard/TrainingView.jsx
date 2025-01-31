import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';
import defaultThumbnail from '../../assets/images/default-course.webp';
import { ChevronLeftIcon, BookOpenIcon, ClockIcon } from '@heroicons/react/24/outline';

const TrainingView = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [training, setTraining] = useState(null);
    const [modules, setModules] = useState([]);

    useEffect(() => {
        fetchTrainingDetails();
        fetchModules();
    }, [id]);

    const fetchTrainingDetails = async () => {
        try {
            const response = await api.get(`/user/trainings/${id}`);
            setTraining(response.data);
        } catch (error) {
            console.error('Erro ao carregar detalhes do treinamento:', error);
            toast.error('Erro ao carregar detalhes do treinamento');
            navigate('/dashboard/trainings');
        }
    };

    const fetchModules = async () => {
        try {
            const response = await api.get(`/user/trainings/${id}/modules`);
            setModules(response.data);
        } catch (error) {
            console.error('Erro ao carregar módulos:', error);
            toast.error('Erro ao carregar módulos');
        } finally {
            setLoading(false);
        }
    };

    const handleStartLesson = (moduleId, lessonId) => {
        // TODO: Implementar navegação para a aula
        navigate(`/dashboard/training/${id}/module/${moduleId}/lesson/${lessonId}`);
    };

    if (loading || !training) {
        return <LoadingOverlay message="Carregando treinamento..." />;
    }

    return (
        <div className="min-h-screen bg-[#141414] py-8 px-8">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="mb-8">
                    <button
                        onClick={() => navigate('/dashboard/trainings')}
                        className="flex items-center text-gray-400 hover:text-white mb-6 transition-colors"
                    >
                        <ChevronLeftIcon className="h-5 w-5 mr-2" />
                        Voltar para Meus Treinamentos
                    </button>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Thumbnail */}
                        <div className="lg:col-span-1">
                            <div className="aspect-video rounded-lg overflow-hidden">
                                <img
                                    src={training.thumbnail || defaultThumbnail}
                                    alt={training.name}
                                    className="w-full h-full object-cover"
                                />
                            </div>
                        </div>

                        {/* Info */}
                        <div className="lg:col-span-2">
                            <h1 className="text-3xl font-bold text-white mb-4">
                                {training.name}
                            </h1>
                            <p className="text-gray-400 mb-6">
                                {training.description}
                            </p>
                            <div className="flex items-center gap-6 text-gray-400">
                                <div className="flex items-center gap-2">
                                    <BookOpenIcon className="h-5 w-5" />
                                    <span>{training.modules_count} módulos</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <ClockIcon className="h-5 w-5" />
                                    <span>{training.lessons_count} aulas</span>
                                </div>
                            </div>
                            {/* Progress bar */}
                            <div className="mt-6">
                                <div className="flex justify-between text-sm mb-2">
                                    <span className="text-gray-400">Progresso</span>
                                    <span className="text-orange-500">{training.progress}%</span>
                                </div>
                                <div className="h-2 bg-gray-700 rounded-full">
                                    <div
                                        className="h-full bg-orange-500 rounded-full transition-all duration-300"
                                        style={{ width: `${training.progress}%` }}
                                    />
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Modules */}
                <div className="space-y-6">
                    {modules.map((module, moduleIndex) => (
                        <div
                            key={module.id}
                            className="bg-gray-900 rounded-lg overflow-hidden"
                        >
                            <div className="p-6">
                                <h3 className="text-xl font-semibold text-white mb-2">
                                    Módulo {moduleIndex + 1}: {module.title}
                                </h3>
                                <p className="text-gray-400 mb-4">
                                    {module.description}
                                </p>
                                <div className="space-y-4">
                                    {module.lessons.map((lesson, lessonIndex) => (
                                        <div
                                            key={lesson.id}
                                            className="flex items-center justify-between p-4 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors cursor-pointer"
                                            onClick={() => handleStartLesson(module.id, lesson.id)}
                                        >
                                            <div>
                                                <h4 className="text-white font-medium">
                                                    {lessonIndex + 1}. {lesson.title}
                                                </h4>
                                                <p className="text-sm text-gray-400">
                                                    {lesson.description}
                                                </p>
                                            </div>
                                            <div className="flex items-center gap-4">
                                                <span className="text-sm text-gray-400">
                                                    {lesson.duration} min
                                                </span>
                                                <button
                                                    className="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg transition-colors"
                                                >
                                                    Iniciar
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default TrainingView; 