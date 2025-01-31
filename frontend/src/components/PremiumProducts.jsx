import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LockClosedIcon, CheckIcon } from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import api from '../services/api';
import defaultThumbnail from '../assets/images/default-course.webp';

const PremiumProducts = ({ variant = 'explore' }) => {
    const navigate = useNavigate();
    const [products, setProducts] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadProducts();
    }, []);

    const loadProducts = async () => {
        try {
            const response = await api.get('/user/products/available');
            setProducts(response.data.products || []);
        } catch (error) {
            toast.error('Erro ao carregar produtos');
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    const handleProductClick = (product) => {
        navigate(`/dashboard/products/${product.id}/order`);
    };

    const ProductCard = ({ product }) => (
        <div 
            className="relative flex-shrink-0 cursor-pointer group"
            onClick={() => handleProductClick(product)}
        >
            <div className="w-[300px] h-[169px] rounded-lg overflow-hidden">
                <img
                    src={product.thumbnail || defaultThumbnail}
                    alt={product.name}
                    className="w-full h-full object-cover transform group-hover:scale-110 transition-transform duration-300"
                />
                {!product.has_access && (
                    <div className="absolute inset-0 bg-black bg-opacity-60 flex items-center justify-center">
                        <LockClosedIcon className="h-8 w-8 text-gray-400" />
                    </div>
                )}
                <div className="absolute inset-0 bg-gradient-to-t from-black/80 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-end p-4">
                    <div>
                        <h3 className="text-lg font-semibold text-white mb-1">{product.name}</h3>
                        <p className="text-sm text-gray-300">{product.description}</p>
                        <div className="mt-2 flex items-center justify-between">
                            <span className="text-orange-500 font-semibold">
                                R$ {Number(product.price).toFixed(2)}
                            </span>
                            {product.has_access ? (
                                <span className="text-green-500 flex items-center">
                                    <CheckIcon className="w-4 h-4 mr-1" />
                                    Disponível
                                </span>
                            ) : (
                                <span className="text-gray-400 flex items-center">
                                    <LockClosedIcon className="w-4 h-4 mr-1" />
                                    Bloqueado
                                </span>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    if (loading) {
        return <div className="p-4">Carregando...</div>;
    }

    // Filtra produtos baseado na variante
    const filteredProducts = variant === 'dashboard' 
        ? products.filter(p => !p.has_access).slice(0, 3)
        : products;

    if (filteredProducts.length === 0) {
        return null;
    }

    return (
        <div className="relative">
            <div className="flex space-x-4 overflow-x-auto px-4 pb-4 scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-gray-900">
                {filteredProducts.map((product) => (
                    <ProductCard key={product.id} product={product} />
                ))}
            </div>
        </div>
    );
};

export default PremiumProducts; 