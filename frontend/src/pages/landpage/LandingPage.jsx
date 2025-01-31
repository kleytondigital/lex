import React, { useState, useEffect } from 'react';
import { useParams, useLocation } from 'react-router-dom';
import api from '../../services/api';
import ClientTemplate from './ClientTemplate';
import ConsultantTemplate from './ConsultantTemplate';

const LandingPage = () => {
    const { digitalName } = useParams();
    const location = useLocation();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [landingPage, setLandingPage] = useState(null);

    // Determinar o tipo de template baseado no path
    const isClientTemplate = location.pathname.startsWith(`/${import.meta.env.VITE_SITE_CLIENTE_URL?.split('/').pop() || 'p'}`);

    useEffect(() => {
        const fetchLandingPage = async () => {
            try {
                // Log para debug
                console.log('Parâmetros:', {
                    digitalName,
                    isClientTemplate,
                    pathname: location.pathname,
                    baseURL: import.meta.env.VITE_API_URL || 'http://lex.aoseudispor.com.br:5000/api'
                });

                const path = `/${isClientTemplate ? 'p' : 'c'}/${digitalName}`;
                console.log('Fazendo requisição para:', path);
                
                const response = await api.get(path);
                console.log('Resposta da API:', response.data);
                setLandingPage(response.data);
            } catch (error) {
                console.error('Erro ao carregar landing page:', error);
                console.error('Detalhes do erro:', {
                    status: error.response?.status,
                    data: error.response?.data,
                    message: error.message,
                    config: error.config // Mostra a configuração completa da requisição
                });
                if (error.response?.status === 404) {
                    setError('Página não encontrada');
                } else {
                    setError(`Erro ao carregar a página: ${error.response?.data?.error || error.message}`);
                }
            } finally {
                setLoading(false);
            }
        };

        fetchLandingPage();
    }, [digitalName, isClientTemplate, location.pathname]);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white">
                <h1 className="text-4xl font-bold mb-4">{error}</h1>
                <p className="text-gray-400">
                    A página que você está procurando não existe ou não está disponível.
                </p>
            </div>
        );
    }

    // Renderizar o template apropriado baseado no path
    return isClientTemplate ? (
        <ClientTemplate data={landingPage} />
    ) : (
        <ConsultantTemplate data={landingPage} />
    );
};

export default LandingPage; 