import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { PlusIcon, Cog6ToothIcon, EyeIcon } from '@heroicons/react/24/solid';
import api from '../../../services/api';
import { toast } from 'react-hot-toast';

const LandingPages = () => {
    const [landingPages, setLandingPages] = useState([]);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    const fetchLandingPages = async () => {
        try {
            const response = await api.get('/landpages');
            setLandingPages(response.data);
        } catch (error) {
            console.error('Erro ao buscar landing pages:', error);
            if (error.response?.status === 401) {
                toast.error('Sua sessão expirou. Por favor, faça login novamente.');
                navigate('/login');
            } else {
                toast.error('Erro ao carregar landing pages');
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchLandingPages();
    }, []);

    if (loading) {
        return <div>Carregando...</div>;
    }

    return (
        <div>
            <div className="md:flex md:items-center md:justify-between mb-6">
                <div className="min-w-0 flex-1">
                    <h2 className="text-2xl font-bold leading-7 text-white sm:truncate sm:text-3xl sm:tracking-tight">
                        Landing Pages
                    </h2>
                </div>
                <div className="mt-4 flex md:ml-4 md:mt-0">
                    <button
                        type="button"
                        onClick={() => navigate('/dashboard/landpage/new')}
                        className="ml-3 inline-flex items-center rounded-md bg-orange-500 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-orange-600"
                    >
                        Nova Landing Page
                    </button>
                </div>
            </div>

            {landingPages.length === 0 ? (
                <p className="text-gray-400">Nenhuma landing page encontrada.</p>
            ) : (
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    {landingPages.map(page => (
                        <div
                            key={page.id}
                            className="bg-gray-900/50 p-4 rounded-lg hover:bg-gray-900/70"
                        >
                            <Link
                                to={`/dashboard/landpage/${page.id}/config`}
                                className="block"
                            >
                                <h3 className="text-lg font-semibold text-white">{page.digital_name}</h3>
                                <div className="flex justify-between items-center mt-2">
                                    <p className="text-gray-400">
                                        {page.objective === 'client' ? 'Captura de Clientes' : 'Captura de Consultores'}
                                    </p>
                                    <span className={`px-2 py-1 text-xs rounded-full ${page.published ? 'bg-green-900/50 text-green-400' : 'bg-gray-800 text-gray-400'}`}>
                                        {page.published ? 'Publicada' : 'Rascunho'}
                                    </span>
                                </div>
                            </Link>
                            <div className="flex justify-between items-center mt-4">
                                <a
                                    href={`/${page.objective === 'client' ? 'p' : 'c'}/${page.digital_name}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-sm text-gray-400 hover:text-white flex items-center"
                                >
                                    <EyeIcon className="h-4 w-4 mr-1" />
                                    Visualizar
                                </a>
                                <Link
                                    to={`/dashboard/landpage/${page.id}/config`}
                                    className="text-sm text-gray-400 hover:text-white flex items-center"
                                >
                                    <Cog6ToothIcon className="h-4 w-4 mr-1" />
                                    Configurar
                                </Link>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default LandingPages;
