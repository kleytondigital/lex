import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import api from '../../services/api';

const CreateTraining = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        name: '',
        description: '',
        category: '',
        price: 0,
        status: 'draft'
    });

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await api.post('/admin/trainings', formData);
            toast.success('Treinamento criado com sucesso!');
            navigate(`/admin/trainings/edit/${response.data.id}`);
        } catch (error) {
            console.error('Erro ao criar treinamento:', error);
            toast.error('Erro ao criar treinamento');
        }
    };

    return (
        <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                <div className="flex items-center justify-between mb-6">
                    <h1 className="text-2xl font-semibold text-gray-200">Criar Novo Treinamento</h1>
                    <button
                        onClick={() => navigate('/admin/trainings')}
                        className="px-4 py-2 text-sm font-medium text-gray-400 bg-gray-800 border border-gray-700 rounded-md hover:bg-gray-700"
                    >
                        Voltar
                    </button>
                </div>

                <div className="bg-gray-900 shadow-lg rounded-lg border border-gray-800">
                    <form onSubmit={handleSubmit} className="p-6 space-y-6">
                        <div>
                            <label htmlFor="name" className="block text-sm font-medium text-gray-300">
                                Nome do Treinamento *
                            </label>
                            <input
                                type="text"
                                name="name"
                                id="name"
                                required
                                value={formData.name}
                                onChange={handleChange}
                                className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded-md shadow-sm py-2 px-3 text-gray-300 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                            />
                        </div>

                        <div>
                            <label htmlFor="description" className="block text-sm font-medium text-gray-300">
                                Descrição
                            </label>
                            <textarea
                                name="description"
                                id="description"
                                rows={4}
                                value={formData.description}
                                onChange={handleChange}
                                className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded-md shadow-sm py-2 px-3 text-gray-300 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                            />
                        </div>

                        <div>
                            <label htmlFor="category" className="block text-sm font-medium text-gray-300">
                                Categoria
                            </label>
                            <input
                                type="text"
                                name="category"
                                id="category"
                                value={formData.category}
                                onChange={handleChange}
                                className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded-md shadow-sm py-2 px-3 text-gray-300 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                            />
                        </div>

                        <div>
                            <label htmlFor="price" className="block text-sm font-medium text-gray-300">
                                Preço (R$)
                            </label>
                            <input
                                type="number"
                                name="price"
                                id="price"
                                min="0"
                                step="0.01"
                                value={formData.price}
                                onChange={handleChange}
                                className="mt-1 block w-full bg-gray-800 border border-gray-700 rounded-md shadow-sm py-2 px-3 text-gray-300 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent"
                            />
                        </div>

                        <div className="flex justify-end space-x-3">
                            <button
                                type="button"
                                onClick={() => navigate('/admin/trainings')}
                                className="px-4 py-2 text-sm font-medium text-gray-400 bg-gray-800 border border-gray-700 rounded-md hover:bg-gray-700"
                            >
                                Cancelar
                            </button>
                            <button
                                type="submit"
                                className="px-4 py-2 text-sm font-medium text-white bg-orange-500 border border-transparent rounded-md hover:bg-orange-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                            >
                                Criar Treinamento
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default CreateTraining; 