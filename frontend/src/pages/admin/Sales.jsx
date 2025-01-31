import { useState, useEffect } from 'react';
import AdminLayout from '../../components/AdminLayout';
import api from '../../services/api';

const AdminSales = () => {
    const [sales, setSales] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchSales();
    }, []);

    const fetchSales = async () => {
        try {
            const response = await api.get('/admin/sales');
            setSales(response.data);
        } catch (error) {
            console.error('Erro ao carregar vendas:', error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <AdminLayout>
            <div className="bg-[#1a1a1a] rounded-lg shadow-lg p-6">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-semibold text-gray-200">Vendas</h2>
                    <div className="flex space-x-4">
                        <select className="bg-[#252525] text-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-orange-500">
                            <option value="all">Todos os Status</option>
                            <option value="completed">Concluído</option>
                            <option value="pending">Pendente</option>
                            <option value="failed">Falhou</option>
                        </select>
                        <input
                            type="date"
                            className="bg-[#252525] text-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-orange-500"
                        />
                    </div>
                </div>

                {loading ? (
                    <div className="flex justify-center items-center h-64">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500"></div>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead className="bg-[#252525] text-gray-300">
                                <tr>
                                    <th className="px-4 py-3 text-left text-sm font-medium rounded-l-lg">ID</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Aluno</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Curso</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Valor</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Data</th>
                                    <th className="px-4 py-3 text-right text-sm font-medium rounded-r-lg">Ações</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-[#252525]">
                                {sales.map((sale) => (
                                    <tr key={sale.id} className="text-gray-300">
                                        <td className="px-4 py-4 font-mono text-sm">#{sale.id}</td>
                                        <td className="px-4 py-4">{sale.student}</td>
                                        <td className="px-4 py-4">{sale.course}</td>
                                        <td className="px-4 py-4">R$ {sale.amount}</td>
                                        <td className="px-4 py-4">
                                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                                                sale.status === 'completed'
                                                    ? 'bg-green-500/20 text-green-500'
                                                    : sale.status === 'pending'
                                                    ? 'bg-yellow-500/20 text-yellow-500'
                                                    : 'bg-red-500/20 text-red-500'
                                            }`}>
                                                {sale.status === 'completed' ? 'Concluído' : 
                                                 sale.status === 'pending' ? 'Pendente' : 'Falhou'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4 text-gray-400">{sale.date}</td>
                                        <td className="px-4 py-4 text-right">
                                            <button className="text-gray-400 hover:text-orange-500 transition-colors">
                                                Detalhes
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </AdminLayout>
    );
};

export default AdminSales; 