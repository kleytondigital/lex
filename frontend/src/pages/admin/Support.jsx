import { useState } from 'react';
import AdminLayout from '../../components/AdminLayout';

const AdminSupport = () => {
    const [tickets, setTickets] = useState([
        {
            id: 1,
            user: 'João Silva',
            subject: 'Problema com acesso ao curso',
            status: 'open',
            priority: 'high',
            created_at: '2024-02-20 14:30'
        },
        // Adicione mais tickets conforme necessário
    ]);

    return (
        <AdminLayout>
            <div className="bg-[#1a1a1a] rounded-lg shadow-lg p-6">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-semibold text-gray-200">Tickets de Suporte</h2>
                    <div className="flex space-x-4">
                        <select className="bg-[#252525] text-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-orange-500">
                            <option value="all">Todos os Status</option>
                            <option value="open">Aberto</option>
                            <option value="in_progress">Em Andamento</option>
                            <option value="closed">Fechado</option>
                        </select>
                        <select className="bg-[#252525] text-gray-300 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-orange-500">
                            <option value="all">Todas as Prioridades</option>
                            <option value="high">Alta</option>
                            <option value="medium">Média</option>
                            <option value="low">Baixa</option>
                        </select>
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead className="bg-[#252525] text-gray-300">
                            <tr>
                                <th className="px-4 py-3 text-left text-sm font-medium rounded-l-lg">ID</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">Usuário</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">Assunto</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">Prioridade</th>
                                <th className="px-4 py-3 text-left text-sm font-medium">Data</th>
                                <th className="px-4 py-3 text-right text-sm font-medium rounded-r-lg">Ações</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#252525]">
                            {tickets.map((ticket) => (
                                <tr key={ticket.id} className="text-gray-300">
                                    <td className="px-4 py-4 font-mono text-sm">#{ticket.id}</td>
                                    <td className="px-4 py-4">{ticket.user}</td>
                                    <td className="px-4 py-4">{ticket.subject}</td>
                                    <td className="px-4 py-4">
                                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                                            ticket.status === 'open'
                                                ? 'bg-green-500/20 text-green-500'
                                                : ticket.status === 'in_progress'
                                                ? 'bg-yellow-500/20 text-yellow-500'
                                                : 'bg-gray-500/20 text-gray-500'
                                        }`}>
                                            {ticket.status === 'open' ? 'Aberto' : 
                                             ticket.status === 'in_progress' ? 'Em Andamento' : 'Fechado'}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4">
                                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                                            ticket.priority === 'high'
                                                ? 'bg-red-500/20 text-red-500'
                                                : ticket.priority === 'medium'
                                                ? 'bg-yellow-500/20 text-yellow-500'
                                                : 'bg-blue-500/20 text-blue-500'
                                        }`}>
                                            {ticket.priority === 'high' ? 'Alta' : 
                                             ticket.priority === 'medium' ? 'Média' : 'Baixa'}
                                        </span>
                                    </td>
                                    <td className="px-4 py-4 text-gray-400">{ticket.created_at}</td>
                                    <td className="px-4 py-4 text-right">
                                        <button className="text-gray-400 hover:text-orange-500 transition-colors">
                                            Responder
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </AdminLayout>
    );
};

export default AdminSupport; 