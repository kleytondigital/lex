import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';
import defaultThumbnail from '../../assets/images/default-course.webp';
import PremiumProducts from '../../components/PremiumProducts';
import useProductAccess from '../../hooks/useProductAccess';

const UserDashboard = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [trainingsInProgress, setTrainingsInProgress] = useState([]);
    const [lockedContent, setLockedContent] = useState([]);
    const [availableTrainings, setAvailableTrainings] = useState([]);
    const { hasAccess: hasLandpageAccess } = useProductAccess('landpage');

    useEffect(() => {
        fetchTrainings();
    }, []);

    const fetchTrainings = async () => {
        try {
            const [inProgressRes, lockedRes, availableRes] = await Promise.all([
                api.get('/user/trainings/in-progress'),
                api.get('/user/trainings/locked'),
                api.get('/user/trainings/available')
            ]);
            setTrainingsInProgress(inProgressRes.data);
            setLockedContent(lockedRes.data);
            setAvailableTrainings(availableRes.data);
        } catch (error) {
            console.error('Erro ao carregar treinamentos:', error);
            toast.error('Erro ao carregar treinamentos');
        } finally {
            setLoading(false);
        }
    };

    const TrainingCard = ({ training, isLocked }) => (
        <div className="relative flex-shrink-0 cursor-pointer group">
            <div className="w-[300px] h-[169px] rounded-lg overflow-hidden">
                <img
                    src={training.thumbnail || defaultThumbnail}
                    alt={training.name}
                    className="w-full h-full object-cover transform group-hover:scale-110 transition-transform duration-300"
                />
                {isLocked && (
                    <div className="absolute inset-0 bg-black bg-opacity-60 flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                    </div>
                )}
                <div className="absolute inset-0 bg-gradient-to-t from-black/80 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-end p-4">
                    <div>
                        <h3 className="text-lg font-semibold text-white mb-1">{training.name}</h3>
                        {training.progress && (
                            <div className="w-full bg-gray-700 rounded-full h-1.5 mb-2">
                                <div
                                    className="bg-orange-500 h-1.5 rounded-full"
                                    style={{ width: `${training.progress}%` }}
                                />
                            </div>
                        )}
                        <p className="text-sm text-gray-300">{training.description}</p>
                    </div>
                </div>
            </div>
        </div>
    );

    const TrainingRow = ({ title, trainings, isLocked }) => (
        <div className="mb-8">
            <h2 className="text-2xl font-semibold text-gray-200 mb-4 px-4">{title}</h2>
            <div className="relative">
                <div className="flex space-x-4 overflow-x-auto px-4 pb-4 scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-gray-900">
                    {trainings.map((training) => (
                        <TrainingCard
                            key={training.id}
                            training={training}
                            isLocked={isLocked}
                        />
                    ))}
                </div>
            </div>
        </div>
    );

    if (loading) {
        return <LoadingOverlay message="Carregando treinamentos..." />;
    }

    return (
        <div className="min-h-screen bg-[#141414] py-8">
            <div className="max-w-[1920px] mx-auto">
                {/* Hero Section - Último treinamento acessado ou destaque */}
                {trainingsInProgress[0] && (
                    <div className="relative h-[500px] mb-8">
                        <div className="absolute inset-0">
                            <img
                                src={trainingsInProgress[0].thumbnail || defaultThumbnail}
                                alt={trainingsInProgress[0].name}
                                className="w-full h-full object-cover"
                            />
                            <div className="absolute inset-0 bg-gradient-to-r from-black/80 via-black/50 to-transparent" />
                        </div>
                        <div className="relative h-full flex items-center px-12">
                            <div className="max-w-2xl">
                                <h1 className="text-4xl font-bold text-white mb-4">
                                    {trainingsInProgress[0].name}
                                </h1>
                                <p className="text-lg text-gray-300 mb-6">
                                    {trainingsInProgress[0].description}
                                </p>
                                <button
                                    onClick={() => navigate(`/dashboard/training/${trainingsInProgress[0].id}`)}
                                    className="bg-orange-500 text-white px-8 py-3 rounded-lg font-semibold hover:bg-orange-600 transition-colors"
                                >
                                    Continuar Assistindo
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {/* Seções de Treinamentos */}
                {trainingsInProgress.length > 0 && (
                    <TrainingRow
                        title="Meus treinamentos em progresso"
                        trainings={trainingsInProgress}
                        isLocked={false}
                    />
                )}

                {availableTrainings.length > 0 && (
                    <TrainingRow
                        title="Treinamentos Disponíveis"
                        trainings={availableTrainings}
                        isLocked={false}
                    />
                )}

                {/* Seção de Produtos Premium */}
                <div className="mb-8 px-4">
                    <h2 className="text-2xl font-semibold text-gray-200 mb-4">Produtos Premium</h2>
                    <p className="text-gray-400 mb-6">
                        Conheça nossos produtos premium e expanda suas possibilidades
                    </p>
                    <PremiumProducts variant="dashboard" />
                </div>

                {lockedContent.length > 0 && (
                    <TrainingRow
                        title="Conteúdo Fechado"
                        trainings={lockedContent}
                        isLocked={true}
                    />
                )}

                {trainingsInProgress.length === 0 && lockedContent.length === 0 && availableTrainings.length === 0 && (
                    <div className="text-center py-20">
                        <svg xmlns="http://www.w3.org/2000/svg" className="mx-auto h-16 w-16 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                        </svg>
                        <h2 className="mt-4 text-2xl font-semibold text-gray-300">
                            Nenhum treinamento disponível
                        </h2>
                        <p className="mt-2 text-gray-500">
                            Você ainda não tem acesso a nenhum treinamento.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default UserDashboard; 