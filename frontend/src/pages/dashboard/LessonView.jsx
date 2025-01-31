import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import ReactPlayer from 'react-player/youtube';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';
import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/react/24/outline';

const LessonView = () => {
    const { id: trainingId, moduleId, lessonId } = useParams();
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [lesson, setLesson] = useState(null);
    const [module, setModule] = useState(null);
    const [nextLesson, setNextLesson] = useState(null);
    const [previousLesson, setPreviousLesson] = useState(null);
    const [playerReady, setPlayerReady] = useState(false);

    useEffect(() => {
        fetchLessonDetails();
        // Reset player state when changing lessons
        setPlayerReady(false);
    }, [trainingId, moduleId, lessonId]);

    const fetchLessonDetails = async () => {
        try {
            const [lessonRes, moduleRes] = await Promise.all([
                api.get(`/user/trainings/${trainingId}/modules/${moduleId}/lessons/${lessonId}`),
                api.get(`/user/trainings/${trainingId}/modules/${moduleId}`)
            ]);

            setLesson(lessonRes.data);
            setModule(moduleRes.data);

            // Encontrar aula anterior e próxima
            const lessons = moduleRes.data.lessons;
            const currentIndex = lessons.findIndex(l => l.id === parseInt(lessonId));
            
            if (currentIndex > 0) {
                setPreviousLesson(lessons[currentIndex - 1]);
            } else {
                setPreviousLesson(null);
            }

            if (currentIndex < lessons.length - 1) {
                setNextLesson(lessons[currentIndex + 1]);
            } else {
                setNextLesson(null);
            }

            // Registrar progresso
            await api.post(`/user/trainings/${trainingId}/progress`, {
                module_id: moduleId,
                lesson_id: lessonId
            });

        } catch (error) {
            console.error('Erro ao carregar detalhes da aula:', error);
            toast.error('Erro ao carregar aula');
            navigate(`/dashboard/training/${trainingId}`);
        } finally {
            setLoading(false);
        }
    };

    const handleNavigateLesson = (lesson) => {
        if (lesson) {
            navigate(`/dashboard/training/${trainingId}/module/${moduleId}/lesson/${lesson.id}`);
        }
    };

    const handlePlayerReady = () => {
        console.log('Player ready');
        setPlayerReady(true);
    };

    const handlePlayerError = (error) => {
        console.error('Player error:', error);
        toast.error('Erro ao carregar o vídeo');
        setPlayerReady(true); // Mostra a interface mesmo com erro
    };

    const handleVideoEnd = async () => {
        try {
            await api.post(`/user/trainings/${trainingId}/progress`, {
                module_id: moduleId,
                lesson_id: lessonId
            });
            
            if (nextLesson) {
                handleNavigateLesson(nextLesson);
            }
        } catch (error) {
            console.error('Erro ao atualizar progresso:', error);
        }
    };

    if (loading || !lesson) {
        return <LoadingOverlay message="Carregando aula..." />;
    }

    return (
        <div className="min-h-screen bg-[#141414]">
            {/* Video Section */}
            <div className="w-full aspect-video bg-black relative">
                {!playerReady && (
                    <div className="absolute inset-0 flex items-center justify-center z-10">
                        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-orange-500"></div>
                    </div>
                )}
                {lesson.content_type === 'video' && (lesson.content || lesson.video_url) && (
                    <div className={`w-full h-full ${!playerReady ? 'opacity-0' : 'opacity-100'} transition-opacity duration-300`}>
                        <ReactPlayer
                            url={lesson.content || lesson.video_url}
                            width="100%"
                            height="100%"
                            controls
                            playing
                            onReady={handlePlayerReady}
                            onError={handlePlayerError}
                            onEnded={handleVideoEnd}
                            config={{
                                youtube: {
                                    playerVars: {
                                        modestbranding: 1,
                                        rel: 0,
                                        showinfo: 0,
                                        controls: 1
                                    }
                                }
                            }}
                        />
                    </div>
                )}
            </div>

            {/* Content Section */}
            <div className="max-w-7xl mx-auto px-4 py-8">
                <button
                    onClick={() => navigate(`/dashboard/training/${trainingId}`)}
                    className="flex items-center text-gray-400 hover:text-white mb-6 transition-colors"
                >
                    <ChevronLeftIcon className="h-5 w-5 mr-2" />
                    Voltar para o treinamento
                </button>

                <div className="bg-gray-900 rounded-lg p-6">
                    <div className="flex justify-between items-start mb-6">
                        <div>
                            <h4 className="text-gray-400 mb-2">
                                {module?.title}
                            </h4>
                            <h1 className="text-2xl font-bold text-white">
                                {lesson.title}
                            </h1>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={() => handleNavigateLesson(previousLesson)}
                                disabled={!previousLesson}
                                className={`p-2 rounded-lg ${
                                    previousLesson
                                        ? 'text-gray-400 hover:text-white hover:bg-gray-800'
                                        : 'text-gray-600 cursor-not-allowed'
                                }`}
                            >
                                <ChevronLeftIcon className="h-6 w-6" />
                            </button>
                            <button
                                onClick={() => handleNavigateLesson(nextLesson)}
                                disabled={!nextLesson}
                                className={`p-2 rounded-lg ${
                                    nextLesson
                                        ? 'text-gray-400 hover:text-white hover:bg-gray-800'
                                        : 'text-gray-600 cursor-not-allowed'
                                }`}
                            >
                                <ChevronRightIcon className="h-6 w-6" />
                            </button>
                        </div>
                    </div>

                    {lesson.description && (
                        <div className="mt-6 text-gray-400">
                            <h3 className="text-lg font-semibold text-white mb-2">
                                Descrição da Aula
                            </h3>
                            <p>{lesson.description}</p>
                        </div>
                    )}

                    {/* Navegação entre aulas */}
                    <div className="mt-8 grid grid-cols-2 gap-4">
                        {previousLesson && (
                            <button
                                onClick={() => handleNavigateLesson(previousLesson)}
                                className="flex items-center justify-start p-4 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors"
                            >
                                <ChevronLeftIcon className="h-5 w-5 mr-2 text-gray-400" />
                                <div className="text-left">
                                    <div className="text-sm text-gray-400">Aula anterior</div>
                                    <div className="text-white">{previousLesson.title}</div>
                                </div>
                            </button>
                        )}
                        {nextLesson && (
                            <button
                                onClick={() => handleNavigateLesson(nextLesson)}
                                className="flex items-center justify-end p-4 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors ml-auto"
                            >
                                <div className="text-right">
                                    <div className="text-sm text-gray-400">Próxima aula</div>
                                    <div className="text-white">{nextLesson.title}</div>
                                </div>
                                <ChevronRightIcon className="h-5 w-5 ml-2 text-gray-400" />
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LessonView; 