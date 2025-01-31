import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import api from '../../services/api';
import defaultThumbnail from '../../assets/images/default-course.webp';
import { CheckIcon } from '@heroicons/react/24/outline';

const ProductOrder = () => {
    const { productId } = useParams();
    const navigate = useNavigate();
    const [product, setProduct] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadProduct();
    }, [productId]);

    const loadProduct = async () => {
        try {
            const response = await api.get(`/user/products/${productId}`);
            setProduct(response.data);
        } catch (error) {
            toast.error('Erro ao carregar produto');
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    const handleBuyClick = async () => {
        try {
            const response = await api.post('/user/orders', {
                productId: product.id
            });
            
            // Redireciona para o checkout com o ID do pedido
            navigate(`/dashboard/checkout/${response.data.orderId}`);
        } catch (error) {
            toast.error('Erro ao criar pedido');
            console.error(error);
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-[#141414] py-8">
                <div className="max-w-7xl mx-auto px-4">
                    <div className="text-white">Carregando...</div>
                </div>
            </div>
        );
    }

    if (!product) {
        return (
            <div className="min-h-screen bg-[#141414] py-8">
                <div className="max-w-7xl mx-auto px-4">
                    <div className="text-white">Produto não encontrado</div>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-[#141414] py-8">
            <div className="max-w-7xl mx-auto px-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    {/* Coluna da Esquerda - Imagem e Detalhes */}
                    <div>
                        <div className="rounded-lg overflow-hidden mb-6">
                            <img
                                src={product.thumbnail || defaultThumbnail}
                                alt={product.name}
                                className="w-full h-[300px] object-cover"
                            />
                        </div>
                        <h1 className="text-3xl font-bold text-white mb-4">
                            {product.name}
                        </h1>
                        <p className="text-gray-300 mb-6">
                            {product.description}
                        </p>
                    </div>

                    {/* Coluna da Direita - Preço e Recursos */}
                    <div className="bg-gray-800 rounded-lg p-6">
                        <div className="mb-6">
                            <h2 className="text-2xl font-bold text-white mb-2">
                                R$ {Number(product.price).toFixed(2)}
                            </h2>
                            <p className="text-gray-400">
                                Pagamento único - Acesso vitalício
                            </p>
                        </div>

                        <div className="mb-6">
                            <h3 className="text-lg font-semibold text-white mb-4">
                                O que está incluído:
                            </h3>
                            <ul className="space-y-3">
                                {product.features?.map((feature, index) => (
                                    <li key={index} className="flex items-start text-gray-300">
                                        <CheckIcon className="w-5 h-5 text-green-500 mr-2 flex-shrink-0 mt-0.5" />
                                        <span>{feature}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>

                        <button
                            onClick={handleBuyClick}
                            className="w-full bg-orange-500 text-white py-3 px-6 rounded-lg font-semibold hover:bg-orange-600 transition-colors"
                        >
                            Comprar Agora
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ProductOrder; 