import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../../services/api';
import { toast } from 'react-hot-toast';

const NewLandingPage = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [formData, setFormData] = useState({
        digitalName: '', // nome-digital-da-pagina
        objective: 'client', // client ou consultant
    });

    const handleChange = (e) => {
        const { name, value } = e.target;
        let processedValue = value;
        
        if (name === 'digitalName') {
            // Remove caracteres especiais e espaços, converte para minúsculas
            processedValue = value
                .toLowerCase()
                .replace(/[^a-z0-9-]/g, '-') // substitui caracteres não permitidos por hífen
                .replace(/-+/g, '-')         // remove hífens múltiplos
                .replace(/^-|-$/g, '');      // remove hífens no início e fim
        }
        
        setFormData(prev => ({
            ...prev,
            [name]: processedValue
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const response = await api.post('/landpages', {
                digitalName: formData.digitalName,
                objective: formData.objective
            });
            toast.success('Landing page criada com sucesso!');
            navigate(`/dashboard/landpage/${response.data.id}/config`);
        } catch (error) {
            console.error('Erro detalhado:', error);
            if (error.response?.status === 401) {
                toast.error('Sua sessão expirou. Por favor, faça login novamente.');
                navigate('/login');
            } else if (error.response?.status === 400) {
                toast.error(error.response.data.error);
            } else {
                toast.error('Erro ao criar landing page');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="max-w-2xl mx-auto">
            <div className="md:flex md:items-center md:justify-between mb-6">
                <div className="min-w-0 flex-1">
                    <h2 className="text-2xl font-bold leading-7 text-white sm:truncate sm:text-3xl sm:tracking-tight">
                        Nova Landing Page
                    </h2>
                </div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6 bg-gray-900/50 p-6 rounded-lg">
                <div className="space-y-4">
                    <div>
                        <label htmlFor="digitalName" className="block text-sm font-medium text-gray-200">
                            Nome Digital
                        </label>
                        <div className="mt-1">
                            <input
                                type="text"
                                name="digitalName"
                                id="digitalName"
                                value={formData.digitalName}
                                onChange={handleChange}
                                className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200 shadow-sm focus:border-orange-500 focus:ring-orange-500 sm:text-sm"
                                placeholder="nome-da-sua-pagina"
                                required
                            />
                            <p className="mt-1 text-sm text-gray-400">
                                Este será o endereço da sua página: seusite.com/p/{formData.digitalName}
                            </p>
                            <p className="mt-1 text-sm text-gray-400">
                                Use apenas letras minúsculas, números e hífens. Espaços serão convertidos em hífens.
                            </p>
                        </div>
                    </div>

                    <div>
                        <label htmlFor="objective" className="block text-sm font-medium text-gray-200">
                            Objetivo da Página
                        </label>
                        <select
                            name="objective"
                            id="objective"
                            value={formData.objective}
                            onChange={handleChange}
                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200 shadow-sm focus:border-orange-500 focus:ring-orange-500 sm:text-sm"
                        >
                            <option value="client">Captura de Clientes</option>
                            <option value="consultant">Captura de Consultores</option>
                        </select>
                    </div>
                </div>

                <div className="flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={() => navigate('/dashboard/landpage')}
                        className="rounded-md bg-gray-800 px-3 py-2 text-sm font-semibold text-gray-200 shadow-sm hover:bg-gray-700"
                    >
                        Cancelar
                    </button>
                    <button
                        type="submit"
                        disabled={loading}
                        className="rounded-md bg-orange-500 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-orange-600 disabled:opacity-50"
                    >
                        {loading ? 'Criando...' : 'Criar Landing Page'}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default NewLandingPage; 