import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import api from '../../services/api';
import MercadoPagoCheckout from '../../components/payment/MercadoPagoCheckout';

const Checkout = () => {
    const { orderId } = useParams();
    const navigate = useNavigate();
    const [order, setOrder] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadOrder();
    }, [orderId]);

    const loadOrder = async () => {
        try {
            const response = await api.get(`/user/orders/${orderId}`);
            setOrder(response.data);
        } catch (error) {
            console.error('Erro ao carregar pedido:', error);
            toast.error('Erro ao carregar pedido');
            navigate('/dashboard');
        } finally {
            setLoading(false);
        }
    };

    const handlePayment = async () => {
        try {
            await api.post(`/user/orders/${orderId}/pay`);
            toast.success('Pagamento realizado com sucesso!');
            navigate('/dashboard');
        } catch (error) {
            console.error('Erro ao processar pagamento:', error);
            toast.error('Erro ao processar pagamento');
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-[#141414] py-8">
                <div className="max-w-3xl mx-auto px-4">
                    <div className="text-white">Carregando...</div>
                </div>
            </div>
        );
    }

    if (!order) {
        return (
            <div className="min-h-screen bg-[#141414] py-8">
                <div className="max-w-3xl mx-auto px-4">
                    <div className="text-white">Pedido não encontrado</div>
                </div>
            </div>
        );
    }

    return (
        <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                <h1 className="text-2xl font-semibold text-gray-300">
                    Checkout
                </h1>
            </div>
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                <div className="py-4">
                    <MercadoPagoCheckout orderId={orderId} />
                </div>
            </div>
        </div>
    );
};

export default Checkout; 