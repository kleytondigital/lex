import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import api from '../../services/api';
import { toast } from 'react-hot-toast';
import LoadingOverlay from '../../components/LoadingOverlay';
import defaultThumbnail from '../../assets/images/default-course.webp';
import { Box, Grid, Typography, Card, CardContent, CardMedia, Button, Modal, Stack } from '@mui/material';

const ExplorePage = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [trainings, setTrainings] = useState([]);
    const [filteredTrainings, setFilteredTrainings] = useState([]);
    const [selectedTraining, setSelectedTraining] = useState(null);
    const [openModal, setOpenModal] = useState(false);

    useEffect(() => {
        fetchTrainings();
    }, []);

    useEffect(() => {
        filterTrainings();
    }, [searchQuery, trainings]);

    const fetchTrainings = async () => {
        try {
            const response = await api.get('/user/trainings/available');
            setTrainings(response.data);
        } catch (error) {
            console.error('Erro ao carregar treinamentos:', error);
            toast.error('Erro ao carregar treinamentos');
        } finally {
            setLoading(false);
        }
    };

    const filterTrainings = () => {
        const filtered = trainings.filter(training =>
            training.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            training.description.toLowerCase().includes(searchQuery.toLowerCase())
        );
        setFilteredTrainings(filtered);
    };

    const handleTrainingClick = (training) => {
        setSelectedTraining(training);
        setOpenModal(true);
    };

    const handleCloseModal = () => {
        setOpenModal(false);
        setSelectedTraining(null);
    };

    const handleViewModules = () => {
        handleCloseModal();
        navigate(`/dashboard/training/${selectedTraining.id}`);
    };

    const handleEnrollTraining = async () => {
        try {
            await api.post(`/user/trainings/${selectedTraining.id}/enroll`);
            toast.success('Matrícula realizada com sucesso!');
            handleCloseModal();
            navigate('/dashboard/trainings');
        } catch (error) {
            console.error('Erro ao matricular:', error);
            toast.error(error.response?.data?.error || 'Erro ao realizar matrícula');
        }
    };

    const TrainingCard = ({ training }) => (
        <div 
            className="group cursor-pointer bg-gray-900 rounded-lg overflow-hidden hover:ring-2 hover:ring-orange-500 transition-all duration-300"
            onClick={() => handleTrainingClick(training)}
        >
            <div className="aspect-video relative">
                <img
                    src={training.thumbnail || defaultThumbnail}
                    alt={training.name}
                    className="w-full h-full object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/40 to-transparent" />
            </div>
            <div className="p-4">
                <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-orange-500 transition-colors">
                    {training.name}
                </h3>
                <p className="text-sm text-gray-400 line-clamp-2">
                    {training.description}
                </p>
                <div className="mt-4 flex items-center gap-2 text-sm text-gray-500">
                    <span>{training.modules_count} módulos</span>
                    <span>•</span>
                    <span>{training.lessons_count} aulas</span>
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
                <div className="flex flex-col gap-8">
                    {/* Search Bar */}
                    <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
                        </div>
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Buscar treinamentos..."
                            className="block w-full pl-10 pr-3 py-2 border border-gray-700 rounded-lg bg-gray-900 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                        />
                    </div>

                    {/* Results */}
                    {filteredTrainings.length > 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                            {filteredTrainings.map((training) => (
                                <TrainingCard key={training.id} training={training} />
                            ))}
                        </div>
                    ) : (
                        <div className="text-center py-20">
                            <MagnifyingGlassIcon className="mx-auto h-12 w-12 text-gray-600" />
                            <h3 className="mt-4 text-lg font-medium text-gray-400">
                                Nenhum treinamento encontrado
                            </h3>
                            <p className="mt-2 text-sm text-gray-500">
                                Tente buscar com outros termos
                            </p>
                        </div>
                    )}
                </div>
            </div>

            {/* Modal */}
            {openModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-gray-900 rounded-lg p-6 max-w-md w-full mx-4">
                        <h2 className="text-xl font-semibold text-white mb-4">
                            {selectedTraining?.name}
                        </h2>
                        <p className="text-gray-400 mb-6">
                            O que você deseja fazer?
                        </p>
                        <div className="flex flex-col gap-3">
                            <button
                                onClick={handleEnrollTraining}
                                className="w-full py-2 px-4 bg-orange-500 hover:bg-orange-600 text-white rounded-lg transition-colors"
                            >
                                Participar do Treinamento
                            </button>
                            <button
                                onClick={handleViewModules}
                                className="w-full py-2 px-4 border border-orange-500 text-orange-500 hover:bg-orange-500 hover:text-white rounded-lg transition-colors"
                            >
                                Ver Módulos
                            </button>
                            <button
                                onClick={handleCloseModal}
                                className="w-full py-2 px-4 text-gray-400 hover:text-white transition-colors"
                            >
                                Cancelar
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ExplorePage; 