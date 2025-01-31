import React, { useState } from 'react';
import { FaTimes, FaWhatsapp } from 'react-icons/fa';

const EconomyModal = ({ isOpen, onClose, consultantWhatsapp }) => {
    const [formData, setFormData] = useState({
        name: '',
        email: ''
    });
    const [showLink, setShowLink] = useState(false);
    const [whatsappUrl, setWhatsappUrl] = useState('');

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        const message = encodeURIComponent(`Olá meu nome é ${formData.name}, meu email é ${formData.email}. Quero obter desconto na minha conta de energia`);
        const url = `https://wa.me/${consultantWhatsapp}?text=${message}`;
        setWhatsappUrl(url);
        setShowLink(true);
    };

    const handleWhatsAppClick = () => {
        window.open(whatsappUrl, '_blank');
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
            <div className="bg-white rounded-lg max-w-md w-full p-6 relative">
                <button
                    onClick={onClose}
                    className="absolute top-4 right-4 text-gray-500 hover:text-gray-700"
                >
                    <FaTimes />
                </button>

                <div className="text-center mb-6">
                    <h2 className="text-2xl font-bold text-gray-900 mb-2">Lex</h2>
                    <h3 className="text-xl font-semibold text-gray-900 mb-4">Seja Bem-vindo(a)!</h3>
                    <p className="text-gray-600 mb-2">
                        Faça como a CacauShow, Positivo, Marista e economize em sua conta de luz até 40%!
                    </p>
                    <p className="text-gray-600 mb-4">
                        Aproveite as condições especiais e exclusivas oferecidas por essa colaboração única.
                    </p>
                </div>

                <div className="space-y-4 mb-6">
                    <div className="bg-orange-100 p-4 rounded-lg">
                        <h4 className="font-semibold text-gray-900 mb-2">1. Prepare sua fatura de energia</h4>
                        <p className="text-gray-600">Tenha sua fatura mais recente em mãos.</p>
                    </div>

                    <div className="bg-orange-100 p-4 rounded-lg">
                        <h4 className="font-semibold text-gray-900 mb-2">2. Envie uma foto</h4>
                        <p className="text-gray-600">Tire uma foto clara da fatura ou faça o upload diretamente.</p>
                    </div>

                    <div className="bg-orange-100 p-4 rounded-lg">
                        <h4 className="font-semibold text-gray-900 mb-2">3. Nós cuidamos do resto!</h4>
                        <p className="text-gray-600">
                            Assinando o contrato, sem necessidade de investimento algum, nós forneceremos o desconto de energia prometido em sua fatura.
                        </p>
                    </div>
                </div>

                {!showLink ? (
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <input
                                type="text"
                                placeholder="Seu nome"
                                required
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                                value={formData.name}
                                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                            />
                        </div>
                        <div>
                            <input
                                type="email"
                                placeholder="Seu e-mail"
                                required
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                                value={formData.email}
                                onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                            />
                        </div>
                        <button
                            type="submit"
                            className="w-full bg-orange-500 text-white py-3 rounded-lg font-semibold hover:bg-orange-600 transition-colors"
                        >
                            Gerar Link
                        </button>
                    </form>
                ) : (
                    <div className="space-y-4">
                        <div className="p-4 bg-gray-100 rounded-lg break-all">
                            <p className="text-sm text-gray-600">Link gerado:</p>
                            <p className="text-gray-900 font-mono text-sm mt-1">{whatsappUrl}</p>
                        </div>
                        <button
                            onClick={handleWhatsAppClick}
                            className="w-full bg-green-600 text-white py-3 rounded-lg font-semibold hover:bg-green-700 transition-colors flex items-center justify-center"
                        >
                            <FaWhatsapp className="mr-2" />
                            Abrir WhatsApp
                        </button>
                        <button
                            onClick={() => setShowLink(false)}
                            className="w-full bg-gray-200 text-gray-700 py-3 rounded-lg font-semibold hover:bg-gray-300 transition-colors"
                        >
                            Voltar
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default EconomyModal; 