import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { Tab } from '@headlessui/react';
import api from '../../../services/api';
import { validateWhatsAppLink, validateEmailLink, formatWhatsAppLink } from '../../../utils/linkValidation';
import LinkPreview from '../../../components/landpage/LinkPreview';
import TemplateSelector from '../../../components/landpage/TemplateSelector';
import { templates } from '../../../data/templates';
import { FaInfoCircle, FaLink, FaCopy, FaExternalLinkAlt, FaAddressCard, FaWhatsapp, FaEnvelope, FaUser, FaBriefcase, FaComment, FaCamera, FaShareAlt, FaTimes } from 'react-icons/fa';

// Adicionar constante para URL base
const BASE_URL = import.meta.env.VITE_API_URL || 'http://lex.aoseudispor.com.br:5000/api';
const SITE_URL = import.meta.env.VITE_SITE_URL || 'http://lex.aoseudispor.com.br:3001';
const CLIENT_URL = import.meta.env.VITE_SITE_CLIENTE_URL || 'http://lex.aoseudispor.com.br:3001/p';
const CONSULTANT_URL = import.meta.env.VITE_SITE_CONSULTANT_URL || 'http://lex.aoseudispor.com.br:3001/c';

// Estado inicial seguro
const initialState = {
    digitalName: '',
    published: false,
    objective: 'client',
    seo: {
        title: '',
        description: '',
        keywords: ''
    },
    content: {
        headline: '',
        subheadline: '',
        videoUrl: '',
        features: [],
        howItWorks: {
            title: '',
            steps: []
        },
        faq: [],
        consultant: {
            name: '',
            role: '',
            message: ''
        }
    },
    integrations: {
        whatsappNumber: '',
        whatsappLink: '',
        referralLink: '',
        webhookUrl: '',
        emailLink: '',
        email: ''
    },
    pixels: {
        facebookPixel: '',
        googleAnalytics: '',
        tiktokPixel: ''
    },
    consultant_name: '',
    consultant_role: '',
    consultant_message: '',
    consultant_photo: '',
    facebook_url: '',
    instagram_url: '',
    linkedin_url: '',
    youtube_url: '',
    tiktok_url: ''
};

const LandingPageConfig = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [isUploading, setIsUploading] = useState(false);
    const [formData, setFormData] = useState(initialState);
    
    console.log('LandingPageConfig montado - ID:', id);  // Log para debug
    
    const fetchLandingPage = async () => {
        try {
            const response = await api.get(`/landpages/${id}/config`);
            console.log('Dados recebidos:', response.data); // Debug
            setFormData({
                ...response.data,
                digitalName: response.data.digital_name || '',
                published: response.data.published || false,
                objective: response.data.objective || 'client',
                seo: {
                    title: response.data.seo?.title || '',
                    description: response.data.seo?.description || '',
                    keywords: response.data.seo?.keywords || ''
                },
                content: {
                    headline: response.data.content?.headline || '',
                    subheadline: response.data.content?.subheadline || '',
                    videoUrl: response.data.content?.videoUrl || '',
                    features: response.data.content?.features || [],
                    howItWorks: response.data.content?.howItWorks || {
                    title: '',
                        steps: []
                    },
                    faq: response.data.content?.faq || [],
                    consultant: response.data.content?.consultant || {
                        name: '',
                        role: '',
                        message: ''
                    }
                },
                integrations: {
                    whatsappNumber: response.data.whatsapp_number || '',
                    whatsappLink: response.data.whatsapp_link || '',
                    referralLink: response.data.referral_link || '',
                    webhookUrl: response.data.integrations?.webhookUrl || '',
                    emailLink: response.data.integrations?.email_integration || '',
                    email: response.data.integrations?.email || ''
                },
                pixels: {
                    facebookPixel: response.data.pixels?.facebookPixel || '',
                    googleAnalytics: response.data.pixels?.googleAnalytics || '',
                    tiktokPixel: response.data.pixels?.tiktokPixel || ''
                },
                consultant_name: response.data.consultant_name || '',
                consultant_role: response.data.consultant_role || '',
                consultant_message: response.data.consultant_message || '',
                consultant_photo: response.data.consultant_photo || '',
                facebook_url: response.data.facebook_url || '',
                instagram_url: response.data.instagram_url || '',
                linkedin_url: response.data.linkedin_url || '',
                youtube_url: response.data.youtube_url || '',
                tiktok_url: response.data.tiktok_url || ''
            });
        } catch (error) {
            console.error('Erro ao carregar:', error);
            toast.error('Erro ao carregar as configurações.');
            setError('Erro ao carregar as configurações da landing page.');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await api.get(`/landpages/${id}/config`);
                const data = response.data;
                
                // Atualiza o formData mantendo a estrutura do estado inicial
                setFormData({
                    ...initialState, // Garante que todas as propriedades existem
                    ...data,
                    content: {
                        ...initialState.content,
                        ...(data.content || {}),
                        howItWorks: {
                            ...initialState.content.howItWorks,
                            ...(data.content?.howItWorks || {}),
                            title: data.content?.howItWorks?.title || '',
                            steps: data.content?.howItWorks?.steps || []
                        },
                        consultant: {
                            ...initialState.content.consultant,
                            ...(data.content?.consultant || {}),
                            name: data.consultant_name || '',
                            role: data.consultant_role || 'Líder de expansão LEX',
                            message: data.consultant_message || 'Olá! Sou especialista em energia solar e estou aqui para ajudar você a economizar na conta de luz. Vamos conversar?'
                        }
                    },
                    integrations: {
                        ...initialState.integrations,
                        ...(data.integrations || {}),
                        whatsappNumber: data.whatsapp_number || '',
                        whatsappLink: data.whatsapp_link || '',
                        referralLink: data.referral_link || '',
                        webhookUrl: data.integrations?.webhookUrl || '',
                        emailLink: data.integrations?.email_integration || '',
                        email: data.integrations?.email || ''
                    },
                    seo: {
                        ...initialState.seo,
                        ...(data.seo || {})
                    },
                    pixels: {
                        ...initialState.pixels,
                        ...(data.pixels || {})
                    }
                });
            } catch (error) {
                console.error('Erro ao carregar:', error);
                toast.error('Erro ao carregar as configurações.');
                setError('Erro ao carregar as configurações da landing page.');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [id]);

    const handleChange = (section, field, value) => {
        if (section === 'integrations' && field === 'whatsappLink') {
            // Formata o link do WhatsApp se necessário
            value = formatWhatsAppLink(value);
            
            // Valida o link do WhatsApp
            const { isValid, message } = validateWhatsAppLink(value);
            if (!isValid) {
                toast.error(message);
                return;
            }
        }

        if (section === 'integrations' && field === 'emailLink') {
            // Valida o link de email
            const { isValid, message } = validateEmailLink(value);
            if (!isValid) {
                toast.error(message);
                return;
            }
        }

        setFormData(prev => {
            // Se o valor é undefined, estamos lidando com um campo direto
            if (value === undefined) {
                return {
                    ...prev,
                    [section]: field // field contém o valor neste caso
                };
            }

            // Se o campo é aninhado, garantimos que a seção existe
            if (section === 'integrations' || section === 'content' || section === 'seo' || section === 'pixels') {
                return {
                    ...prev,
                    [section]: {
                        ...(prev[section] || {}), // Garante que a seção existe
                        [field]: value
                    }
                };
            }

            // Campo direto normal
            return {
                ...prev,
                [section]: {
                    ...prev[section],
                    [field]: value
                }
            };
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setSaving(true);
        try {
            // Formatar os dados antes de enviar
            const dataToSend = {
                ...formData,
                digital_name: formData.digitalName,
                whatsapp_number: formData.integrations.whatsappNumber,
                whatsapp_link: formData.integrations.whatsappNumber ? `https://wa.me/${formData.integrations.whatsappNumber}` : '',
                referral_link: formData.integrations.referralLink,
                integrations: {
                    ...formData.integrations,
                    email_integration: formData.integrations.emailLink,
                },
                seo: formData.seo,
                content: formData.content,
                pixels: formData.pixels,
                consultant_name: formData.consultant_name,
                consultant_role: formData.consultant_role,
                consultant_message: formData.consultant_message,
                consultant_photo: formData.consultant_photo,
                facebook_url: formData.facebook_url,
                instagram_url: formData.instagram_url,
                linkedin_url: formData.linkedin_url,
                youtube_url: formData.youtube_url,
                tiktok_url: formData.tiktok_url
            };

            console.log('Dados a serem enviados:', dataToSend); // Debug

            await api.put(`/landpages/${id}/config`, dataToSend);
            toast.success('Configurações salvas com sucesso!');
        } catch (error) {
            console.error('Erro ao salvar:', error);
            toast.error('Erro ao salvar as configurações.');
        } finally {
            setSaving(false);
        }
    };

    const handleTemplateSelect = (template) => {
        setFormData(prev => ({
            ...prev,
            template: template.id,
            content: {
                ...template.defaultContent,
                consultant: {
                    name: prev.consultant_name || template.defaultContent.consultant.name,
                    role: prev.consultant_role || template.defaultContent.consultant.role,
                    message: prev.consultant_message || template.defaultContent.consultant.message
                }
            }
        }));
    };

    const handleContentChange = (field, value) => {
        if (field === 'consultant') {
            // Atualiza tanto o content.consultant quanto os campos principais do consultor
            setFormData(prev => ({
                ...prev,
                content: {
                    ...prev.content,
                    consultant: {
                        ...prev.content.consultant,
                        ...value
                    }
                },
                consultant_name: value.name || prev.consultant_name,
                consultant_role: value.role || prev.consultant_role,
                consultant_message: value.message || prev.consultant_message
            }));
        } else {
        setFormData(prev => ({
            ...prev,
            content: {
                ...prev.content,
                [field]: typeof value === 'object' ? {
                    ...(prev.content[field] || {}),
                    ...value
                } : value
            }
        }));
        }
    };

    const getPageUrl = () => {
        // Extrair os paths das variáveis de ambiente
        const clientPath = import.meta.env.VITE_SITE_CLIENTE_URL || 'http://lex.aoseudispor.com.br:3001/p';
        const consultantPath = import.meta.env.VITE_SITE_CONSULTANT_URL || 'http://lex.aoseudispor.com.br:3001/c';
        
        // Usar o path correto baseado no objetivo da landing page
        const baseUrl = formData.objective === 'client' ? clientPath : consultantPath;
        
        // Construir a URL completa
        return `${baseUrl}/${formData.digitalName}`;
    };

    const handlePhotoUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        // Validar tamanho do arquivo (máximo 5MB)
        const maxSize = 5 * 1024 * 1024; // 5MB
        if (file.size > maxSize) {
            toast.error('A imagem deve ter no máximo 5MB');
            return;
        }

        // Validar tipo do arquivo
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
        if (!allowedTypes.includes(file.type)) {
            toast.error('Apenas imagens JPG e PNG são permitidas');
            return;
        }

        setIsUploading(true);
        setUploadProgress(0);
        const formData = new FormData();
        formData.append('photo', file);

        try {
            const response = await api.post('/landpages/upload-photo', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
                onUploadProgress: (progressEvent) => {
                    const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                    setUploadProgress(progress);
                }
            });

            // Atualiza o estado com apenas o nome do arquivo
            const photoUrl = `/uploads/${response.data.filename}`;
            handleChange('consultant_photo', photoUrl);
            toast.success('Foto enviada com sucesso!');
        } catch (error) {
            console.error('Erro ao fazer upload da foto:', error);
            toast.error(error.response?.data?.error || 'Erro ao fazer upload da foto');
        } finally {
            setIsUploading(false);
            setUploadProgress(0);
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="text-center py-12">
                <p className="text-red-500">{error}</p>
                <button
                    onClick={() => navigate('/dashboard/landpage')}
                    className="mt-4 text-white hover:text-orange-500"
                >
                    Voltar para lista
                </button>
            </div>
        );
    }

    return (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="md:flex md:items-center md:justify-between mb-6">
                <div className="min-w-0 flex-1">
                    <h2 className="text-2xl font-bold leading-7 text-white sm:truncate sm:text-3xl sm:tracking-tight">
                        Configurações da Landing Page
                    </h2>
                </div>
            </div>

            <Tab.Group>
                <Tab.List className="flex space-x-1 rounded-xl bg-gray-900/20 p-1">
                    <Tab className={({ selected }) =>
                        `w-full rounded-lg py-2.5 text-sm font-medium leading-5
                        ${selected 
                            ? 'bg-orange-500 text-white shadow'
                            : 'text-gray-400 hover:bg-gray-800/20 hover:text-white'
                        }`
                    }>
                        Geral
                    </Tab>
                    <Tab className={({ selected }) =>
                        `w-full rounded-lg py-2.5 text-sm font-medium leading-5
                        ${selected 
                            ? 'bg-orange-500 text-white shadow'
                            : 'text-gray-400 hover:bg-gray-800/20 hover:text-white'
                        }`
                    }>
                        Template
                    </Tab>
                    <Tab className={({ selected }) =>
                        `w-full rounded-lg py-2.5 text-sm font-medium leading-5
                        ${selected 
                            ? 'bg-orange-500 text-white shadow'
                            : 'text-gray-400 hover:bg-gray-800/20 hover:text-white'
                        }`
                    }>
                        SEO
                    </Tab>
                    <Tab className={({ selected }) =>
                        `w-full rounded-lg py-2.5 text-sm font-medium leading-5
                        ${selected 
                            ? 'bg-orange-500 text-white shadow'
                            : 'text-gray-400 hover:bg-gray-800/20 hover:text-white'
                        }`
                    }>
                        Integrações
                    </Tab>
                    <Tab className={({ selected }) =>
                        `w-full rounded-lg py-2.5 text-sm font-medium leading-5
                        ${selected 
                            ? 'bg-orange-500 text-white shadow'
                            : 'text-gray-400 hover:bg-gray-800/20 hover:text-white'
                        }`
                    }>
                        Pixels
                    </Tab>
                    <Tab className={({ selected }) =>
                        `w-full rounded-lg py-2.5 text-sm font-medium leading-5
                        ${selected 
                            ? 'bg-orange-500 text-white shadow'
                            : 'text-gray-400 hover:bg-gray-800/20 hover:text-white'
                        }`
                    }>
                        Conteúdo
                    </Tab>
                </Tab.List>

                <Tab.Panels className="mt-6">
                    {/* Painel Geral */}
                    <Tab.Panel className="bg-gray-900/50 rounded-xl p-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            {/* Card de Informações Básicas */}
                            <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
                                <div className="flex items-center mb-4">
                                    <FaInfoCircle className="text-orange-500 text-xl mr-2" />
                                    <h3 className="text-lg font-medium text-gray-200">Informações Básicas</h3>
                                </div>

                                <div className="space-y-4">
                    <div>
                                <label className="block text-sm font-medium text-gray-200">
                            Nome Digital
                        </label>
                                        <div className="mt-1 relative">
                        <input
                            type="text"
                                                name="digitalName"
                            value={formData.digitalName}
                                                onChange={(e) => {
                                                    const newValue = e.target.value;
                                                    if (newValue !== formData.digitalName) {
                                                        toast.warning('Alterar o nome digital afetará o link de acesso à página');
                                                    }
                                                    handleChange('digitalName', newValue);
                                                }}
                                                className="block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                                placeholder="nome-da-pagina"
                                                readOnly
                                            />
                                            <div className="absolute inset-y-0 right-0 flex items-center pr-3">
                                                <FaLink className="text-gray-400" />
                                            </div>
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-200 mb-2">
                                            Link da Página
                                        </label>
                                        <div className="flex items-center space-x-2 bg-gray-900 p-2 rounded-md">
                                            <input
                                                type="text"
                                                value={getPageUrl()}
                                                className="flex-1 bg-transparent text-gray-200 border-none focus:ring-0"
                                                readOnly
                                            />
                                            <button
                                                onClick={() => {
                                                    navigator.clipboard.writeText(getPageUrl());
                                                    toast.success('Link copiado!');
                                                }}
                                                className="text-orange-500 hover:text-orange-400"
                                                title="Copiar link"
                                            >
                                                <FaCopy className="text-lg" />
                                            </button>
                                            <button
                                                onClick={() => window.open(getPageUrl(), '_blank')}
                                                className="text-orange-500 hover:text-orange-400"
                                                title="Abrir página"
                                            >
                                                <FaExternalLinkAlt className="text-lg" />
                                            </button>
                                        </div>
                                    </div>

                                    <div className="flex items-center justify-between mt-4">
                                        <span className="text-sm font-medium text-gray-200">Status da Página</span>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked={formData.published}
                                                onChange={(e) => handleChange('published', e.target.checked)}
                                                className="sr-only peer"
                                            />
                                            <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer 
                                                peer-checked:after:translate-x-full peer-checked:after:border-white 
                                                after:content-[''] after:absolute after:top-[2px] after:left-[2px] 
                                                after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all 
                                                peer-checked:bg-orange-500">
                                            </div>
                                        </label>
                                    </div>
                                </div>
                            </div>

                            {/* Card WhatsApp e Compartilhamento */}
                            <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
                                <div className="flex items-center mb-4">
                                    <FaWhatsapp className="text-orange-500 text-xl mr-2" />
                                    <h3 className="text-lg font-medium text-gray-200">WhatsApp e Compartilhamento</h3>
                                </div>

                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            Número do WhatsApp
                                        </label>
                                        <input
                                            type="text"
                                            id="whatsappNumber"
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500 sm:text-sm"
                                            placeholder="Ex: 5511999999999"
                                            value={formData?.integrations?.whatsappNumber ?? ''}
                                            onChange={(e) => handleChange('integrations', 'whatsappNumber', e.target.value)}
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            Link de Indicação
                                        </label>
                                        <input
                                            type="url"
                                            value={formData.integrations.referralLink || ''}
                                            onChange={(e) => handleChange('integrations', 'referralLink', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                            placeholder="Link de indicação da Alexandria"
                                        />
                                    </div>
                                </div>
                            </div>

                            {/* Card Redes Sociais */}
                            <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
                                <div className="flex items-center mb-4">
                                    <FaShareAlt className="text-orange-500 text-xl mr-2" />
                                    <h3 className="text-lg font-medium text-gray-200">Redes Sociais</h3>
                                </div>

                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            Facebook
                                        </label>
                                        <input
                                            type="url"
                                            value={formData.facebook_url || ''}
                                            onChange={(e) => handleChange('facebook_url', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                            placeholder="URL do perfil do Facebook"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            Instagram
                                        </label>
                                        <input
                                            type="url"
                                            value={formData.instagram_url || ''}
                                            onChange={(e) => handleChange('instagram_url', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                            placeholder="URL do perfil do Instagram"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            LinkedIn
                                        </label>
                                        <input
                                            type="url"
                                            value={formData.linkedin_url || ''}
                                            onChange={(e) => handleChange('linkedin_url', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                            placeholder="URL do perfil do LinkedIn"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            YouTube
                                        </label>
                                        <input
                                            type="url"
                                            value={formData.youtube_url || ''}
                                            onChange={(e) => handleChange('youtube_url', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                            placeholder="URL do canal do YouTube"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-sm font-medium text-gray-200">
                                            TikTok
                                        </label>
                                        <input
                                            type="url"
                                            value={formData.tiktok_url || ''}
                                            onChange={(e) => handleChange('tiktok_url', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                            placeholder="URL do perfil do TikTok"
                                        />
                                    </div>
                                </div>
                            </div>

                            {/* Consultant Data Card */}
                            <div className="bg-gray-800 p-4 rounded-lg">
                                                                <div className="flex items-center mb-4">
                                    <FaInfoCircle className="text-orange-500 text-xl mr-2" />
                                    <h3 className="text-lg font-medium text-gray-200">Dados Consultor</h3>
                                </div>
                                <div className="space-y-4">
                                    <div className="flex items-center space-x-2">
                                        <FaUser className="text-orange-500" />
                                        <input
                                            type="text"
                                            placeholder="Nome do Consultor"
                                            value={formData.consultant_name || ''}
                                            onChange={(e) => handleChange('consultant_name', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                        />
                                    </div>

                                    <div className="flex items-center space-x-2">
                                        <FaBriefcase className="text-orange-500" />
                                        <input
                                            type="text"
                                            placeholder="Cargo"
                                            value={formData.consultant_role || 'Líder de expansão LEX'}
                                            onChange={(e) => handleChange('consultant_role', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200"
                                        />
                                    </div>

                                    <div className="flex items-center space-x-2">
                                        <FaComment className="text-orange-500" />
                                        <textarea
                                            placeholder="Mensagem de apresentação"
                                            value={formData.consultant_message || 'Olá! Sou especialista em energia solar e estou aqui para ajudar você a economizar na conta de luz. Vamos conversar?'}
                                            onChange={(e) => handleChange('consultant_message', e.target.value)}
                                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-900 text-gray-200 h-24"
                                        />
                                    </div>

                                    <div className="flex items-center space-x-2">
                                        <FaCamera className="text-orange-500" />
                                        <div className="flex-1">
                                            <input
                                                type="file"
                                                accept="image/*"
                                                onChange={handlePhotoUpload}
                                                className="hidden"
                                                id="consultant-photo"
                                                disabled={isUploading}
                                            />
                                            <label
                                                htmlFor="consultant-photo"
                                                className={`cursor-pointer bg-gray-700 text-white rounded p-2 w-full block text-center hover:bg-gray-600 transition-colors ${isUploading ? 'opacity-50 cursor-not-allowed' : ''}`}
                                            >
                                                {isUploading ? 'Enviando...' : formData.consultant_photo ? 'Alterar Foto' : 'Upload da Foto'}
                                            </label>
                                        </div>
                                    </div>

                                    {isUploading && (
                                        <div className="mt-2">
                                            <div className="w-full bg-gray-700 rounded-full h-2.5">
                                                <div
                                                    className="bg-orange-500 h-2.5 rounded-full transition-all duration-300"
                                                    style={{ width: `${uploadProgress}%` }}
                                                ></div>
                                            </div>
                                            <p className="text-sm text-gray-400 text-center mt-1">
                                                {uploadProgress}% concluído
                                            </p>
                                        </div>
                                    )}

                                    {formData.consultant_photo && !isUploading && (
                                        <div className="mt-2">
                                            <div className="relative">
                                                <img
                                                    src={formData.consultant_photo}
                                                    alt="Foto do Consultor"
                                                    className="w-32 h-32 object-cover rounded-full mx-auto"
                                                />
                                                <button
                                                    onClick={() => {
                                                        handleChange('consultant_photo', '');
                                                        toast.success('Foto removida com sucesso!');
                                                    }}
                                                    className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full p-1 hover:bg-red-600 transition-colors"
                                                    title="Remover foto"
                                                >
                                                    <FaTimes className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </Tab.Panel>

                    {/* Painel Template */}
                    <Tab.Panel className="bg-gray-900/50 rounded-xl p-6">
                        <TemplateSelector
                            objective={formData.objective}
                            currentTemplate={formData.template}
                            onSelect={handleTemplateSelect}
                        />

                        <div className="mt-8 space-y-6">
                            <h3 className="text-lg font-medium text-gray-200">Configurações do Template</h3>
                            
                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Nome do Consultor
                                </label>
                                <input
                                    type="text"
                                    value={formData.content.consultant?.name || ''}
                                    onChange={(e) => handleContentChange('consultant', { 
                                        ...formData.content.consultant,
                                        name: e.target.value 
                                    })}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="Ex: João Silva"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Cargo/Função
                                </label>
                                <input
                                    type="text"
                                    value={formData.content.consultant?.role || ''}
                                    onChange={(e) => handleContentChange('consultant', {
                                        ...formData.content.consultant,
                                        role: e.target.value
                                    })}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="Ex: Consultor Master"
                        />
                    </div>

                    <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Mensagem do Consultor
                        </label>
                                <textarea
                                    value={formData.content.consultant?.message || ''}
                                    onChange={(e) => handleContentChange('consultant', {
                                        ...formData.content.consultant,
                                        message: e.target.value
                                    })}
                                    rows={3}
                            className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="Ex: Olá! Sou consultor há X anos..."
                                />
                </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    URL do Vídeo (YouTube ou Vimeo)
                                </label>
                    <input
                                    type="text"
                                    value={formData.content.videoUrl || ''}
                                    onChange={(e) => handleContentChange('videoUrl', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="Ex: https://www.youtube.com/embed/..."
                                />
                                <p className="mt-1 text-sm text-gray-400">
                                    Use o link de incorporação do vídeo. Se deixar vazio, será usado o vídeo padrão do sistema.
                                </p>
                </div>
                        </div>
                    </Tab.Panel>

                    {/* Painel SEO */}
                    <Tab.Panel className="bg-gray-900/50 rounded-xl p-6">
                        <div className="space-y-6">
                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Título SEO
                                </label>
                                <input
                                    type="text"
                                    value={formData.seo.title || ''}
                                    onChange={(e) => handleChange('seo', 'title', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Descrição
                                </label>
                                <textarea
                                    value={formData.seo.description || ''}
                                    onChange={(e) => handleChange('seo', 'description', e.target.value)}
                                    rows={3}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Palavras-chave
                                </label>
                                <input
                                    type="text"
                                    value={formData.seo.keywords || ''}
                                    onChange={(e) => handleChange('seo', 'keywords', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="Separe as palavras-chave por vírgula"
                                />
                            </div>
                        </div>
                    </Tab.Panel>

                    {/* Painel Integrações */}
                    <Tab.Panel className="bg-gray-900/50 rounded-xl p-6">
                        <div className="space-y-6">
                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Link de Cadastro WhatsApp
                                </label>
                                <input
                                    type="url"
                                    value={formData.integrations.whatsappLink}
                                    onChange={(e) => handleChange('integrations', 'whatsappLink', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="https://wa.me/seu-numero"
                                />
                                <p className="mt-1 text-sm text-gray-400">
                                    Link para direcionamento ao WhatsApp após cadastro
                                </p>
                                <LinkPreview 
                                    link={formData.integrations.whatsappLink} 
                                    type="whatsapp" 
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Link de Cadastro Email
                                </label>
                                <input
                                    type="url"
                                    value={formData.integrations.emailLink || ''}
                                    onChange={(e) => handleChange('integrations', 'emailLink', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="https://seu-site.com/cadastro-email"
                                />
                                <p className="mt-1 text-sm text-gray-400">
                                    Link para direcionamento ao formulário de email após cadastro
                                </p>
                                <LinkPreview 
                                    link={formData.integrations.emailLink} 
                                    type="email" 
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    URL do Webhook (Opcional)
                                </label>
                                <input
                                    type="url"
                                    value={formData.integrations.webhookUrl || ''}
                                    onChange={(e) => handleChange('integrations', 'webhookUrl', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="https://seu-site.com/webhook"
                                />
                                <p className="mt-1 text-sm text-gray-400">
                                    URL para receber notificações de novos leads
                                </p>
                            </div>
                        </div>
                    </Tab.Panel>

                    {/* Painel Pixels */}
                    <Tab.Panel className="bg-gray-900/50 rounded-xl p-6">
                        <div className="space-y-6">
                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Facebook Pixel ID
                                </label>
                                <input
                                    type="text"
                                    value={formData.pixels.facebookPixel || ''}
                                    onChange={(e) => handleChange('pixels', 'facebookPixel', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Google Analytics ID
                                </label>
                                <input
                                    type="text"
                                    value={formData.pixels.googleAnalytics || ''}
                                    onChange={(e) => handleChange('pixels', 'googleAnalytics', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    TikTok Pixel ID
                                </label>
                                <input
                                    type="text"
                                    value={formData.pixels.tiktokPixel || ''}
                                    onChange={(e) => handleChange('pixels', 'tiktokPixel', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>
                        </div>
                    </Tab.Panel>

                    {/* Painel Conteúdo */}
                    <Tab.Panel className="bg-gray-900/50 rounded-xl p-6">
                        <div className="space-y-6">
                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Headline
                                </label>
                                <input
                                    type="text"
                                        value={formData.content.headline || ''}
                                    onChange={(e) => handleContentChange('headline', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Subheadline
                                </label>
                                <input
                                    type="text"
                                    value={formData.content.subheadline || ''}
                                    onChange={(e) => handleContentChange('subheadline', e.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    URL do Vídeo (YouTube ou Vimeo)
                                </label>
                                <input
                                    type="text"
                                    value={formData.content.videoUrl || ''}
                                    onChange={(e) => handleContentChange('videoUrl', e.target.value)}
                                    placeholder="Ex: https://www.youtube.com/embed/..."
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                />
                                <p className="mt-1 text-sm text-gray-400">
                                    Use o link de incorporação do vídeo. Se deixar vazio, será usado o vídeo padrão do sistema.
                                </p>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-200">
                                    Título do "Como Funciona"
                                </label>
                                <input
                                    type="text"
                                    value={formData?.content?.howItWorks?.title ?? ''}
                                    onChange={(e) => handleContentChange('howItWorks', { 
                                        ...formData.content?.howItWorks,
                                        title: e.target.value 
                                    })}
                                    className="mt-1 block w-full rounded-md border-gray-700 bg-gray-800 text-gray-200"
                                    placeholder="Ex: Como funciona nossa solução"
                                />
                            </div>
                        </div>
                    </Tab.Panel>
                </Tab.Panels>
            </Tab.Group>

            <div className="mt-6 flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={() => navigate('/dashboard/landpage')}
                        className="rounded-md bg-gray-800 px-3 py-2 text-sm font-semibold text-gray-200"
                    >
                        Cancelar
                    </button>
                    <button
                    type="button"
                    onClick={handleSubmit}
                        disabled={saving}
                        className="rounded-md bg-orange-500 px-3 py-2 text-sm font-semibold text-white disabled:opacity-50"
                    >
                        {saving ? 'Salvando...' : 'Salvar Alterações'}
                    </button>
                </div>
        </div>
    );
};

export default LandingPageConfig;
