import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import api from '../../services/api';

const MercadoPagoCheckout = ({ orderId }) => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const loadMercadoPago = async () => {
            try {
                // Carregar script do Mercado Pago
                const script = document.createElement('script');
                script.src = 'https://sdk.mercadopago.com/js/v2';
                script.async = true;
                document.body.appendChild(script);

                script.onload = async () => {
                    try {
                        // Simular pagamento bem-sucedido (temporário)
                        await api.post(`/user/orders/${orderId}/pay`);
                        toast.success('Pagamento processado com sucesso!');
                        navigate('/dashboard');
                        
                        setLoading(false);
                    } catch (error) {
                        console.error('Erro ao carregar checkout:', error);
                        setError('Erro ao carregar opções de pagamento');
                        setLoading(false);
                    }
                };

                script.onerror = () => {
                    setError('Erro ao carregar Mercado Pago');
                    setLoading(false);
                };

            } catch (error) {
                setError('Erro ao inicializar pagamento');
                setLoading(false);
            }
        };

        loadMercadoPago();

        return () => {
            // Limpar script ao desmontar
            const script = document.querySelector('script[src="https://sdk.mercadopago.com/js/v2"]');
            if (script) {
                document.body.removeChild(script);
            }
        };
    }, [orderId, navigate]);

    if (loading) {
        return (
            <div className="flex justify-center items-center p-8">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="text-center p-8">
                <p className="text-red-500 mb-4">{error}</p>
                <button
                    onClick={() => navigate('/dashboard')}
                    className="px-4 py-2 bg-orange-500 text-white rounded hover:bg-orange-600"
                >
                    Voltar para o Dashboard
                </button>
            </div>
        );
    }

    return (
        <div className="p-8">
            <div className="max-w-2xl mx-auto bg-[#1a1a1a] rounded-lg shadow-lg p-6">
                <h2 className="text-xl font-semibold text-gray-200 mb-6">
                    Finalizar Pagamento
                </h2>
                
                <div className="mb-6">
                    <p className="text-gray-300 mb-2">
                        Escolha a forma de pagamento:
                    </p>
                    <ul className="text-gray-400 text-sm mb-4">
                        <li>• Cartão de Crédito em até 12x</li>
                        <li>• PIX com pagamento instantâneo</li>
                    </ul>
                </div>

                {/* Container para o botão do Mercado Pago */}
                <div className="cho-container"></div>

                <div className="mt-6 text-center">
                    <button
                        onClick={() => navigate('/dashboard')}
                        className="text-gray-400 hover:text-gray-300 text-sm"
                    >
                        Voltar para o Dashboard
                    </button>
                </div>
            </div>
        </div>
    );
};

export default MercadoPagoCheckout; 