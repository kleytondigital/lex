// Formulário de configuração das landing pages 
import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import ImageUpload from './ImageUpload';
import api from '../../services/api';

const ConfigForm = ({ type }) => {
    const { orderId } = useParams();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);
    const [config, setConfig] = useState({
        headline: '',
        consultantPhoto: '',
        contactEmail: '',
        contactWhatsapp: '',
        referralLink: '',
        showVideo: true,
        showCompanyImages: true,
        showSocialProof: true,
        status: 'draft'
    });

    useEffect(() => {
        loadConfig();
    }, []);

    const loadConfig = async () => {
        try {
            const { data } = await api.get(`/landpage/config?type=${type}`);
            setConfig(data);
        } catch (error) {
            setError('Erro ao carregar configurações');
        }
    };

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setConfig(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess(false);

        try {
            await api.put(`/landpage/config/${orderId}`, {
                ...config,
                type
            });
            setSuccess(true);
        } catch (error) {
            setError(error.response?.data?.error || 'Erro ao salvar configurações');
        } finally {
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            <div>
                <h3 className="text-lg font-medium text-gray-300 mb-4">
                    Configurações da Landing Page - {type === 'client' ? 'Clientes' : 'Consultores'}
                </h3>

                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            Headline Principal
                        </label>
                        <input
                            type="text"
                            name="headline"
                            value={config.headline}
                            onChange={handleChange}
                            className="mt-1 block w-full rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                        />
                    </div>

                    <ImageUpload
                        currentImage={config.consultantPhoto}
                        onUploadSuccess={(url) => setConfig(prev => ({
                            ...prev,
                            consultantPhoto: url
                        }))}
                    />

                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            Email de Contato
                        </label>
                        <input
                            type="email"
                            name="contactEmail"
                            value={config.contactEmail}
                            onChange={handleChange}
                            className="mt-1 block w-full rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            WhatsApp
                        </label>
                        <input
                            type="tel"
                            name="contactWhatsapp"
                            value={config.contactWhatsapp}
                            onChange={handleChange}
                            className="mt-1 block w-full rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            Link de Indicação
                        </label>
                        <input
                            type="url"
                            name="referralLink"
                            value={config.referralLink}
                            onChange={handleChange}
                            className="mt-1 block w-full rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                        />
                    </div>

                    <div className="space-y-2">
                        <div className="flex items-center">
                            <input
                                type="checkbox"
                                name="showVideo"
                                checked={config.showVideo}
                                onChange={handleChange}
                                className="rounded bg-[#2a2a2a] border-gray-600 text-orange-600 focus:ring-orange-500"
                            />
                            <label className="ml-2 text-sm text-gray-400">
                                Mostrar Vídeo
                            </label>
                        </div>

                        <div className="flex items-center">
                            <input
                                type="checkbox"
                                name="showCompanyImages"
                                checked={config.showCompanyImages}
                                onChange={handleChange}
                                className="rounded bg-[#2a2a2a] border-gray-600 text-orange-600 focus:ring-orange-500"
                            />
                            <label className="ml-2 text-sm text-gray-400">
                                Mostrar Imagens da Empresa
                            </label>
                        </div>

                        <div className="flex items-center">
                            <input
                                type="checkbox"
                                name="showSocialProof"
                                checked={config.showSocialProof}
                                onChange={handleChange}
                                className="rounded bg-[#2a2a2a] border-gray-600 text-orange-600 focus:ring-orange-500"
                            />
                            <label className="ml-2 text-sm text-gray-400">
                                Mostrar Provas Sociais
                            </label>
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            Status
                        </label>
                        <select
                            name="status"
                            value={config.status}
                            onChange={handleChange}
                            className="mt-1 block w-full rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                        >
                            <option value="draft">Rascunho</option>
                            <option value="published">Publicado</option>
                        </select>
                    </div>
                </div>
            </div>

            {error && (
                <div className="text-red-400 text-sm">{error}</div>
            )}

            {success && (
                <div className="text-green-400 text-sm">
                    Configurações salvas com sucesso!
                </div>
            )}

            <div className="flex justify-end">
                <button
                    type="submit"
                    disabled={loading}
                    className="px-4 py-2 bg-orange-600 text-white rounded-md hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 disabled:opacity-50"
                >
                    {loading ? 'Salvando...' : 'Salvar Configurações'}
                </button>
            </div>
        </form>
    );
};

export default ConfigForm; 