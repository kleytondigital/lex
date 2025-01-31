import React from 'react';
import { FaWhatsapp, FaCheck, FaArrowRight } from 'react-icons/fa';

const SolarLoading = () => {
    return (
        <div className="flex justify-center items-center min-h-screen bg-gray-900">
            <div className="relative w-24 h-24">
                {/* Sol */}
                <div className="absolute w-full h-full rounded-full bg-yellow-500 animate-pulse"></div>
                {/* Raios de sol */}
                {[...Array(8)].map((_, i) => (
                    <div
                        key={i}
                        className="absolute w-2 h-8 bg-yellow-500 rounded-full"
                        style={{
                            top: '50%',
                            left: '50%',
                            transform: `translate(-50%, -50%) rotate(${i * 45}deg) translateY(-40px)`,
                        }}
                    ></div>
                ))}
            </div>
        </div>
    );
};

const ConsultantTemplate = ({ data }) => {
    if (!data || !data.content) {
        return <SolarLoading />;
    }

    const { content, seo = {}, integrations = {} } = data;
    const defaultVideo = import.meta.env.VITE_DEFAULT_CONSULTANT_VIDEO;

    return (
        <div className="min-h-screen bg-gradient-to-b from-gray-900 via-gray-800 to-gray-900 text-white">
            {/* SEO */}
            {seo.title && <title>{seo.title}</title>}
            {seo.description && <meta name="description" content={seo.description} />}
            {seo.keywords && <meta name="keywords" content={seo.keywords} />}

            {/* Hero Section */}
            <div className="container mx-auto px-4 py-16">
                <div className="max-w-4xl mx-auto text-center">
                    <h1 className="text-4xl md:text-5xl font-bold mb-8 leading-tight bg-clip-text text-transparent bg-gradient-to-r from-orange-400 to-yellow-500">
                        {content.headline || 'Bem-vindo'}
                    </h1>
                    <p className="text-xl md:text-2xl text-gray-300 mb-12">
                        {content.subheadline || ''}
                    </p>

                    {/* Video Section */}
                    <div className="mb-12">
                        <div className="aspect-video rounded-lg overflow-hidden bg-gray-800 shadow-lg hover:shadow-2xl transition-shadow duration-300">
                            <iframe
                                src={`${content.videoUrl || defaultVideo}?rel=0&modestbranding=1&showinfo=0&controls=1&disablekb=1`}
                                title="Apresentação"
                                className="w-full h-full"
                                frameBorder="0"
                                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                                allowFullScreen
                            />
                        </div>
                    </div>

                    {content.cta && integrations.whatsappLink && (
                        <div className="flex flex-col md:flex-row gap-4 justify-center">
                            <a
                                href={integrations.whatsappLink}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center justify-center px-8 py-4 bg-solar-gradient text-white rounded-lg text-lg font-semibold transition-all duration-300 hover:bg-solar-gradient hover:scale-105 shadow-lg hover:shadow-xl"
                            >
                                <FaWhatsapp className="mr-2" />
                                {content.cta.primary || 'Falar no WhatsApp'}
                            </a>
                        </div>
                    )}
                </div>
            </div>

            {/* Features Section */}
            {content.features && content.features.length > 0 && (
                <div className="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 py-16">
                    <div className="container mx-auto px-4">
                        <div className="max-w-4xl mx-auto">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {content.features.map((feature, index) => (
                                    <div key={index} className="flex items-start space-x-4 bg-gray-800/50 p-6 rounded-lg hover:bg-gray-800/70 transition-colors duration-300">
                                        <div className="flex-shrink-0">
                                            <div className="w-8 h-8 rounded-full bg-gradient-to-r from-orange-400 to-yellow-500 flex items-center justify-center">
                                                <FaCheck className="h-4 w-4 text-white" />
                                            </div>
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
                            <h2 className="text-3xl font-bold text-center mb-12 bg-clip-text text-transparent bg-gradient-to-r from-orange-400 to-yellow-500">
                                {content.howItWorks.title || 'Como Funciona'}
                            </h2>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {content.howItWorks.steps.map((step, index) => (
                                    <div key={index} className="flex items-start space-x-4 bg-gray-800/50 p-6 rounded-lg hover:bg-gray-800/70 transition-colors duration-300">
                                        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-solar-gradient flex items-center justify-center">
                                            <span className="font-bold text-white">{index + 1}</span>
                                        </div>
                                        <p className="text-lg text-gray-300">{step}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Consultant Section */}
            {content.consultant && (
                <div className="py-16">
                    <div className="container mx-auto px-4">
                        <div className="max-w-4xl mx-auto text-center">
                            <div className="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 rounded-lg p-8 shadow-2xl">
                                <div className="mb-6">
                                    <h3 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-orange-400 to-yellow-500">
                                        {content.consultant.name || ''}
                                    </h3>
                                    <p className="text-orange-500 font-semibold">{content.consultant.role || ''}</p>
                                </div>
                                <p className="text-lg text-gray-300 mb-8 italic">{content.consultant.message || ''}</p>
                                {content.cta && integrations.whatsappLink && (
                                    <a
                                        href={integrations.whatsappLink}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="inline-flex items-center justify-center px-8 py-4 bg-solar-gradient text-white rounded-lg text-lg font-semibold transition-all duration-300 hover:bg-solar-gradient hover:scale-105 shadow-lg hover:shadow-xl"
                                    >
                                        <FaWhatsapp className="mr-2" />
                                        {content.cta.secondary || 'Falar no WhatsApp'}
                                    </a>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Adicionar os keyframes e classes personalizadas */}
            <style jsx>{`
                .bg-solar-gradient {
                    background: linear-gradient(135deg, #FFA500, #FF4500);
                }

                .hover\\:bg-solar-gradient:hover {
                    background: linear-gradient(135deg, #FF4500, #FFA500);
                }

                @keyframes pulse {
                    0%, 100% {
                        transform: scale(1);
                        box-shadow: 0 0 0 0 rgba(255, 165, 0, 0.7);
                    }
                    50% {
                        transform: scale(1.05);
                        box-shadow: 0 0 20px 10px rgba(255, 165, 0, 0.3);
                    }
                }

                @keyframes glow {
                    0% {
                        box-shadow: 0 0 5px rgba(255, 165, 0, 0.5),
                                0 0 10px rgba(255, 165, 0, 0.5),
                                0 0 15px rgba(255, 165, 0, 0.5);
                    }
                    100% {
                        box-shadow: 0 0 10px rgba(255, 165, 0, 0.8),
                                0 0 20px rgba(255, 165, 0, 0.8),
                                0 0 30px rgba(255, 165, 0, 0.8);
                    }
                }
            `}</style>
        </div>
    );
}

export default ConsultantTemplate; 