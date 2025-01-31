import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DashboardLayout from '../../components/DashboardLayout';
import api from '../../services/api';

const Products = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [products, setProducts] = useState([]);
    const [showModal, setShowModal] = useState(false);
    const [selectedProduct, setSelectedProduct] = useState(null);
    const [digitalName, setDigitalName] = useState('');
    const [formError, setFormError] = useState('');

    useEffect(() => {
        loadProducts();
    }, []);

    const loadProducts = async () => {
        try {
            const { data } = await api.get('/landpage/products');
            setProducts(data);
        } catch (error) {
            setError('Erro ao carregar produtos');
            console.error('Erro:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleProductSelect = (product) => {
        setSelectedProduct(product);
        setShowModal(true);
        setFormError('');
        setDigitalName('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setFormError('');

        if (!digitalName.trim()) {
            setFormError('Digite um nome digital válido');
            return;
        }

        try {
            const { data } = await api.post('/landpage/orders', {
                productId: selectedProduct.id,
                digitalName: digitalName.trim().toLowerCase()
            });

            navigate(`/dashboard/checkout/${data.orderId}`);
        } catch (error) {
            setFormError(error.response?.data?.error || 'Erro ao criar pedido');
        }
    };

    if (loading) {
        return (
            <DashboardLayout>
                <div className="flex justify-center items-center h-screen">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
                </div>
            </DashboardLayout>
        );
    }

    return (
        <DashboardLayout>
            <div className="py-6">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                    <h1 className="text-2xl font-semibold text-gray-300">
                        Produtos Premium
                    </h1>
                </div>

                <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8 mt-8">
                    {error ? (
                        <div className="text-red-500 text-center">{error}</div>
                    ) : (
                        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                            {products.map((product) => (
                                <div
                                    key={product.id}
                                    className="bg-[#1a1a1a] rounded-lg shadow-lg overflow-hidden"
                                >
                                    <div className="p-6">
                                        <h3 className="text-lg font-medium text-gray-200">
                                            {product.name}
                                        </h3>
                                        <p className="mt-2 text-gray-400">
                                            {product.description}
                                        </p>
                                        <div className="mt-4">
                                            <span className="text-2xl font-bold text-orange-500">
                                                R$ {product.price.toFixed(2)}
                                            </span>
                                        </div>
                                        <button
                                            onClick={() => handleProductSelect(product)}
                                            className="mt-4 w-full px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                                        >
                                            Solicitar Agora
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Modal de Nome Digital */}
            {showModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
                    <div className="bg-[#1a1a1a] rounded-lg max-w-md w-full p-6">
                        <h3 className="text-lg font-medium text-gray-200 mb-4">
                            Escolha seu nome digital
                        </h3>
                        <form onSubmit={handleSubmit}>
                            <div className="mb-4">
                                <label className="block text-sm font-medium text-gray-400 mb-2">
                                    Nome Digital
                                </label>
                                <input
                                    type="text"
                                    value={digitalName}
                                    onChange={(e) => setDigitalName(e.target.value)}
                                    className="w-full px-3 py-2 bg-[#2a2a2a] border border-gray-700 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                    placeholder="seu-nome-digital"
                                />
                                {formError && (
                                    <p className="mt-2 text-sm text-red-500">
                                        {formError}
                                    </p>
                                )}
                            </div>
                            <div className="flex justify-end space-x-3">
                                <button
                                    type="button"
                                    onClick={() => setShowModal(false)}
                                    className="px-4 py-2 text-sm font-medium text-gray-400 hover:text-gray-300"
                                >
                                    Cancelar
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 text-sm font-medium text-white bg-orange-600 rounded-md hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                                >
                                    Continuar
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </DashboardLayout>
    );
};

export default Products; 