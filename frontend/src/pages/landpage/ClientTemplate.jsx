import React, { useState, useEffect } from 'react';
import { FaWhatsapp, FaCheck, FaArrowRight } from 'react-icons/fa';
import ReactPlayer from 'react-player';
import EconomyModal from '../../components/landpage/EconomyModal';

const ClientTemplate = ({ data }) => {
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [mediaVideos, setMediaVideos] = useState([]);

    useEffect(() => {
        // Get all media videos from environment variable
        const allVideos = (import.meta.env.VITE_MEDIA_VIDEOS || '').split(',').filter(Boolean);
        
        // Shuffle and get 3 random videos
        const shuffledVideos = allVideos.sort(() => Math.random() - 0.5);
        setMediaVideos(shuffledVideos.slice(0, 3));
    }, []);

    if (!data || !data.content) {
        return <div>Loading...</div>;
    }

    const { content, seo = {}, integrations = {} } = data;
    const defaultVideo = import.meta.env.VITE_DEFAULT_CLIENT_VIDEO;
    const defaultVideoInstitucional = import.meta.env.VITE_INSTITUCIONAL_VIDEO;

    // Garantir que todos os dados necessários estejam disponíveis
    const consultantData = {
        name: content?.consultant?.name || '',
        role: content?.consultant?.role || 'Líder de expansão LEX',
        message: content?.consultant?.message || 'Olá! Sou especialista em energia solar e estou aqui para ajudar você a economizar na conta de luz. Vamos conversar?',
        photo: data.consultant_photo || ''
    };

    const socialLinks = {
        facebook: data.facebook_url || '',
        instagram: data.instagram_url || '',
        linkedin: data.linkedin_url || '',
        youtube: data.youtube_url || '',
        tiktok: data.tiktok_url || ''
    };

    const whatsappData = {
        number: integrations.whatsappNumber || '',
        link: integrations.whatsappLink || '',
        referralLink: integrations.referralLink || ''
    };

    return (
        <div className="min-h-screen bg-gradient-to-b from-gray-900 to-gray-800 text-white">
            {/* SEO */}
            {seo.title && <title>{seo.title}</title>}
            {seo.description && <meta name="description" content={seo.description} />}
            {seo.keywords && <meta name="keywords" content={seo.keywords} />}

            {/* Hero Section */}
            <div className="container mx-auto px-4 py-16">
                <div className="max-w-4xl mx-auto text-center">
                    <h1 className="text-4xl md:text-5xl font-bold mb-8 leading-tight">
                        {content.headline || 'Bem-vindo'}
                    </h1>
                    <p className="text-xl md:text-2xl text-gray-300 mb-12">
                        {content.subheadline || ''}
                    </p>

                    {/* Video Section */}
                    <div className="mb-12">
                        <div className="aspect-video rounded-lg overflow-hidden bg-gray-800">
                            <ReactPlayer
                                url={content.videoUrl || defaultVideo}
                                width="100%"
                                height="100%"
                                controls={false}
                                playing={true}
                                playsinline={true}
                                config={{
                                    youtube: {
                                        playerVars: {
                                            showinfo: 0,
                                            rel: 0,
                                            modestbranding: 1,
                                            playsinline: 1,
                                            controls: 0,
                                            disablekb: 1,
                                            fs: 0,
                                            iv_load_policy: 3
                                        }
                                    }
                                }}
                            />
                        </div>
                    </div>

                    {/* CTA Buttons */}
                    <div className="flex flex-col md:flex-row gap-4 justify-center">
                        <button
                            onClick={() => setIsModalOpen(true)}
                            className="inline-flex items-center justify-center px-8 py-4 bg-orange-500 hover:bg-orange-600 rounded-lg text-lg font-semibold transition-all duration-300 animate-pulse hover:animate-none hover:scale-105 relative overflow-hidden group"
                        >
                            <span className="absolute inset-0 bg-gradient-to-r from-orange-400 to-orange-600 opacity-0 group-hover:opacity-50 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-500"></span>
                            <span className="relative">
                                QUERO ECONOMIZAR AGORA
                            </span>
                        </button>

                        {whatsappData.link && (
                            <a
                                href={whatsappData.link}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center justify-center px-8 py-4 bg-green-600 hover:bg-green-700 rounded-lg text-lg font-semibold transition-all duration-300 animate-pulse hover:animate-none hover:scale-105 relative overflow-hidden group"
                            >
                                <span className="absolute inset-0 bg-gradient-to-r from-green-500 to-green-700 opacity-0 group-hover:opacity-50 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-500"></span>
                                <span className="relative">
                                    <FaWhatsapp className="inline-block mr-2" />
                                    ATENDIMENTO NO WHATSAPP
                                </span>
                            </a>
                        )}
                    </div>

                    {/* Economy Modal */}
                    <EconomyModal
                        isOpen={isModalOpen}
                        onClose={() => setIsModalOpen(false)}
                        consultantWhatsapp={whatsappData.number}
                        consultantName={consultantData.name}
                    />
                </div>
            </div>

            {/* Seção Somos Alexandria */}
            <section className="py-16 bg-gray-900/50">
                <div className="container mx-auto px-4">
                    <div className="max-w-6xl mx-auto">
                        <h2 className="text-4xl font-bold text-center mb-12">SOMOS A ALEXANDRIA</h2>
                        <div className="grid md:grid-cols-2 gap-8 items-center">
                            <div className="relative rounded-lg overflow-hidden">
                                <img
                                    src="/images/alexandria-energia.webp"
                                    alt="Alexandria Energia Solar"
                                    className="w-auto h-auto object-cover"
                                />
                                <div className="absolute inset-0 bg-gradient-to-t from-gray-900/80 to-transparent">
                                    <div className="absolute bottom-4 left-4">
                                        <img
                                            src="/images/logo-alexandria.png"
                                            alt="Logo Alexandria"
                                            className="h-12"
                                        />
                                        <p className="text-sm mt-2">A energia em seu poder.</p>
                                    </div>
                                </div>
                            </div>
                            <div className="space-y-4">
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        A Alexandria é uma empresa brasileira que atua no setor de energia, oferecendo soluções inovadoras e sustentáveis para consumidores residenciais e empresariais
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Fundada em 2017, a empresa tem como missão democratizar o acesso à produção, uso e comercialização de energia, colocando esse poder ao alcance de pessoas e organizações
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Hoje, somos uma das maiores empresas de energia e tecnologia do Brasil
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                    Temos amplo conhecimento do mercado de energia e um sólido e excelente relacionamento com os maiores geradores do mundo
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                    Nossos especialistas estão equipados para oferecer soluções eficientes e personalizadas, visando a economia de energia e sustentabilidade                                
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                            <p className="text-gray-300">
                                    Nosso compromisso é atender às necessidades específicas de cada cliente, aproveitando nosso conhecimento profundo e abrangente do mercado                                    
                            </p>
                                
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Seção Conheça a Alexandria */}
            <section className="py-16">
                <div className="container mx-auto px-4">
                    <div className="max-w-6xl mx-auto">
                        <h2 className="text-4xl font-bold text-center mb-12">CONHEÇA A ALEXANDRIA</h2>
                        <div className="aspect-video rounded-lg overflow-hidden">
                            <ReactPlayer
                                url={defaultVideoInstitucional}
                                width="100%"
                                height="100%"
                                controls={true}
                                playing={false}
                                playsinline={true}
                            />
                        </div>
                    </div>
                </div>
            </section>

            {/* Seção Como Funciona a Energia Solar */}
            <section className="py-16 bg-gray-900/50">
                <div className="container mx-auto px-4">
                    <div className="max-w-6xl mx-auto">
                        <h2 className="text-4xl font-bold text-center mb-12">
                            COMO FUNCIONA A ENERGIA SOLAR DA ALEXANDRIA
                        </h2>
                        <div className="grid md:grid-cols-2 gap-8 items-center">
                            <div className="relative  rounded-lg overflow-hidden">
                                <img
                                    src="/images/energia-solar-funcionamento.webp"
                                    alt="Como funciona a energia solar"
                                    className="w-auto h-auto object-cover"
                                />
                            </div>
                            <div className="space-y-4">
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Nossas usinas produzem energia solar, a energia é injetada na rede da distribuidora, a distribuidora envia a energia para sua residência ou empresa, você economiza de forma gratuita sem investimentos
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Como a nossa energia solar é mais barata do que a energia hidrelétrica normalmente utilizada pelas distribuidoras, nós conseguimos oferecer um desconto de até 40% por mês para nossos clientes
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Você não paga nenhum centavo para ter acesso a esses descontos, não precisa instalar placas solares, não alteramos sua instalação de energia, não tem obras, não tem taxa de adesão, não tem mensalidade, não tem fidelidade
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Todo o cadastro é 100% online, gratuito e realizado em poucos minutos
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                                    <p className="text-gray-300">
                                        Nós atendemos casas, apartamentos, prédios, condomínios, fazendas, comércios e empresas
                                    </p>
                                </div>
                                <div className="flex items-start space-x-3">
                                    <div className="flex-shrink-0">
                                        <div className="w-2 h-2 mt-2 rounded-full bg-orange-500"></div>
                                    </div>
                            <p className="text-gray-300">
                                        Nosso trabalho está regulamentado pela Lei Federal 14.300 de 6 de Janeiro de 2022. Os consumidores já podem escolher o tipo de energia que desejam utilizar em suas residências e empresas, se é a energia hidrelétrica ou a energia solar renovável e mais barata
                            </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Seção O Que a Mídia Diz Sobre a Energia Solar */}
            <section className="py-16">
                <div className="container mx-auto px-4">
                    <div className="max-w-6xl mx-auto">
                        <h2 className="text-4xl font-bold text-center mb-12">
                            O QUE A MÍDIA DIZ SOBRE A ENERGIA SOLAR
                        </h2>
                        <div className="grid md:grid-cols-3 gap-8">
                            {mediaVideos.map((videoUrl, index) => (
                                <div key={index} className="aspect-video rounded-lg overflow-hidden bg-gray-800">
                                    <ReactPlayer
                                        url={videoUrl}
                                        width="100%"
                                        height="100%"
                                        controls={true}
                                        playing={false}
                                        playsinline={true}
                                    />
                                </div>
                            ))}
                    </div>
                </div>
            </div>
            </section>

            {/* Seção Como Funciona a Portabilidade de Energia */}
            <section className="py-16 bg-gray-900/50">
                <div className="container mx-auto px-4">
                    <div className="max-w-6xl mx-auto">
                        <h2 className="text-4xl font-bold text-center mb-12">
                            COMO FUNCIONA A PORTABILIDADE DE ENERGIA
                        </h2>
                        
                        {/* Vídeo em cima */}
                        <div className="aspect-video rounded-lg overflow-hidden bg-gray-800 mb-8">
                                <ReactPlayer
                                    url={import.meta.env.VITE_PORTABILIDADE}
                                    width="100%"
                                    height="100%"
                                    controls={true}
                                    playing={false}
                                    playsinline={true}
                            />
                        </div>

                        {/* Imagens em duas colunas abaixo */}
                        <div className="grid md:grid-cols-2 gap-8">
                            <div className="relative rounded-lg overflow-hidden">
                                <img
                                    src="/images/portabilidade.webp"
                                    alt="Portabilidade de Energia"
                                    className="w-full h-auto object-cover"
                                />
                            </div>
                            <div className="relative rounded-lg overflow-hidden">
                                <img
                                    src="/images/com-alexandria.webp"
                                    alt="Com Alexandria"
                                    className="w-full h-auto object-cover"
                                />
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Features Section */}
            {content.features && content.features.length > 0 && (
                <div className="bg-gray-800/50 py-16">
                    <div className="container mx-auto px-4">
                        <div className="max-w-4xl mx-auto">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {content.features.map((feature, index) => (
                                    <div key={index} className="flex items-start space-x-4">
                                        <div className="flex-shrink-0">
                                            <FaCheck className="h-6 w-6 text-green-500" />
                                        </div>
                                        <p className="text-lg text-gray-300">{feature}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* How it Works Section */}
            {content.howItWorks && content.howItWorks.steps && content.howItWorks.steps.length > 0 && (
                <div className="py-16">
                    <div className="container mx-auto px-4">
                        <div className="max-w-4xl mx-auto">
                            <h2 className="text-3xl font-bold text-center mb-12">
                                {content.howItWorks.title || 'Como Funciona'}
                            </h2>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {content.howItWorks.steps.map((step, index) => (
                                    <div key={index} className="flex items-start space-x-4">
                                        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-orange-500 flex items-center justify-center">
                                            <span className="font-bold">{index + 1}</span>
                                        </div>
                                        <p className="text-lg text-gray-300">{step}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* FAQ Section */}
            {content.faq && content.faq.length > 0 && (
                <div className="bg-gray-800/50 py-16">
                    <div className="container mx-auto px-4">
                        <div className="max-w-4xl mx-auto">
                            <h2 className="text-3xl font-bold text-center mb-12">
                                Perguntas Frequentes
                            </h2>
                            <div className="space-y-8">
                                {content.faq.map((item, index) => (
                                    <div key={index} className="bg-gray-900/50 rounded-lg p-6">
                                        <h3 className="text-xl font-semibold mb-4">{item.question}</h3>
                                        <p className="text-gray-300">{item.answer}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Consultant Section */}
            {consultantData.name && (
                <div className="py-16">
                    <div className="container mx-auto px-4">
                        <div className="max-w-6xl mx-auto">
                            <div className="bg-gray-900/50 rounded-lg p-8">
                                <div className="grid md:grid-cols-2 gap-8 items-center">
                                    {/* Conteúdo do Consultor */}
                                    <div className="text-left">
                                        <h3 className="text-3xl font-bold mb-2">{consultantData.name}</h3>
                                        <p className="text-orange-500 font-semibold text-xl mb-6">{consultantData.role}</p>
                                        <p className="text-xl text-gray-300 mb-8 italic">
                                            "{consultantData.message}"
                                        </p>
                                    </div>

                                    {/* Foto do Consultor */}
                                    <div className="relative">
                                        {consultantData.photo && (
                                            <img
                                                src={consultantData.photo}
                                                alt={consultantData.name}
                                                className="w-full h-auto rounded-lg shadow-2xl"
                                            />
                                        )}
                                    </div>
                                </div>

                                {/* Seção de CTA e Logo */}
                                <div className="mt-12 text-center">
                                    <div className="flex flex-col md:flex-row gap-6 justify-center mb-8">
                                        <button
                                            onClick={() => setIsModalOpen(true)}
                                            className="inline-flex items-center justify-center px-8 py-4 bg-orange-500 hover:bg-orange-600 rounded-lg text-lg font-semibold transition-all duration-300 animate-pulse hover:animate-none hover:scale-105 relative overflow-hidden group"
                                        >
                                            <span className="absolute inset-0 bg-gradient-to-r from-orange-400 to-orange-600 opacity-0 group-hover:opacity-50 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-500"></span>
                                            <span className="relative">
                                                QUERO ECONOMIZAR AGORA
                                            </span>
                                        </button>

                                        {whatsappData.link && (
                                            <a
                                                href={whatsappData.link}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="inline-flex items-center justify-center px-8 py-4 bg-green-600 hover:bg-green-700 rounded-lg text-lg font-semibold transition-all duration-300 animate-pulse hover:animate-none hover:scale-105 relative overflow-hidden group"
                                            >
                                                <span className="absolute inset-0 bg-gradient-to-r from-green-500 to-green-700 opacity-0 group-hover:opacity-50 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-500"></span>
                                                <span className="relative">
                                                    <FaWhatsapp className="inline-block mr-2" />
                                                    ATENDIMENTO NO WHATSAPP
                                                </span>
                                            </a>
                                        )}
                                    </div>

                                    {/* Logo e Nome do Consultor */}
                                    <div className="flex flex-col items-center">
                                        <img
                                            src="/images/logo-alexandria.png"
                                            alt="Logo Alexandria"
                                            className="h-16 mb-4"
                                        />
                                        <p className="text-xl font-semibold">
                                            {consultantData.name} | CONSULTOR ALEXANDRIA
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Adicionar os keyframes para as animações no início do arquivo */}
            <style jsx>{`
                @keyframes pulse {
                    0%, 100% {
                        transform: scale(1);
                        box-shadow: 0 0 0 0 rgba(249, 115, 22, 0.7);
                    }
                    50% {
                        transform: scale(1.05);
                        box-shadow: 0 0 20px 10px rgba(249, 115, 22, 0.3);
                    }
                }

                @keyframes glow {
                    0% {
                        box-shadow: 0 0 5px rgba(249, 115, 22, 0.5),
                                0 0 10px rgba(249, 115, 22, 0.5),
                                0 0 15px rgba(249, 115, 22, 0.5);
                    }
                    100% {
                        box-shadow: 0 0 10px rgba(249, 115, 22, 0.8),
                                0 0 20px rgba(249, 115, 22, 0.8),
                                0 0 30px rgba(249, 115, 22, 0.8);
                    }
                }
            `}</style>
        </div>
    );
};

export default ClientTemplate; 