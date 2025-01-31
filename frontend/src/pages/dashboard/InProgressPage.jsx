import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';
import defaultThumbnail from '../../assets/images/default-course.webp';

const InProgressPage = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [trainings, setTrainings] = useState([]);

    useEffect(() => {
        fetchTrainings();
    }, []);

    const fetchTrainings = async () => {
        try {
            const response = await api.get('/user/trainings/in-progress');
            setTrainings(response.data);
        } catch (error) {
            console.error('Erro ao carregar treinamentos:', error);
            toast.error('Erro ao carregar treinamentos');
        } finally {
            setLoading(false);
        }
    };

    const TrainingCard = ({ training }) => (
        <div 
            className="group cursor-pointer bg-gray-900 rounded-lg overflow-hidden hover:ring-2 hover:ring-orange-500 transition-all duration-300"
            onClick={() => navigate(`/dashboard/training/${training.id}`)}
        >
            <div className="aspect-video relative">
                <img
                    src={training.thumbnail || defaultThumbnail}
                    alt={training.name}
                    className="w-full h-full object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/40 to-transparent" />
                {/* Progress bar */}
                <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-700">
                    <div 
                        className="h-full bg-orange-500 transition-all duration-300"
                        style={{ width: `${training.progress}%` }}
                    />
                </div>
            </div>
            <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-orange-500 transition-colors">
                    {training.name}
                </h3>
                <p className="text-sm text-gray-400 line-clamp-2">
                    {training.description}
                </p>
                <div className="mt-4 flex items-center justify-between">
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                        <span>{training.modules_count} módulos</span>
                        <span>•</span>
                        <span>{training.lessons_count} aulas</span>
                    </div>
                    <span className="text-sm text-orange-500">
                        {training.progress}% concluído
                    </span>
                </div>
            </div>
        </div>
    );

    if (loading) {
        return <LoadingOverlay message="Carregando treinamentos..." />;
    }

    return (
        <div className="min-h-screen bg-[#141414] py-8 px-8">
            <div className="max-w-7xl mx-auto">
                <h1 className="text-2xl font-bold text-white mb-8">
                    Meus Treinamentos
                </h1>

                {trainings.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                        {trainings.map((training) => (
                            <TrainingCard key={training.id} training={training} />
                        ))}
                    </div>
                ) : (
                    <div className="text-center py-20">
                        <h3 className="text-lg font-medium text-gray-400">
                            Você ainda não está participando de nenhum treinamento
                        </h3>
                        <button
                            onClick={() => navigate('/dashboard/explore')}
                            className="mt-4 px-6 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg transition-colors"
                        >
                            Explorar Treinamentos
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default InProgressPage; 