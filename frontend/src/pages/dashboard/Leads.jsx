// Página para consultor visualizar e gerenciar seus leads
// - Lista de leads
// - Filtros
// - Exportação 

import { useState, useEffect } from 'react';
import { format } from 'date-fns';
import { ptBR } from 'date-fns/locale';
import DashboardLayout from '../../components/DashboardLayout';
import api from '../../services/api';

const Leads = () => {
    const [leads, setLeads] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [filter, setFilter] = useState('all'); // all, client, consultant
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        loadLeads();
    }, []);

    const loadLeads = async () => {
        try {
            const { data } = await api.get('/landpage/leads');
            setLeads(data);
        } catch (error) {
            setError('Erro ao carregar leads');
        } finally {
            setLoading(false);
        }
    };

    const filteredLeads = leads
        .filter(lead => {
            if (filter === 'all') return true;
            return lead.type === filter;
        })
        .filter(lead => {
            if (!searchTerm) return true;
            const term = searchTerm.toLowerCase();
            return (
                lead.name.toLowerCase().includes(term) ||
                lead.email.toLowerCase().includes(term) ||
                lead.phone.includes(term)
            );
        });

    const exportToCSV = () => {
        const headers = ['Nome', 'Email', 'Telefone', 'Tipo', 'Data'];
        const csvData = filteredLeads.map(lead => [
            lead.name,
            lead.email,
            lead.phone,
            lead.type === 'client' ? 'Cliente' : 'Consultor',
            format(new Date(lead.created_at), 'dd/MM/yyyy HH:mm')
        ]);

        const csvContent = [
            headers.join(','),
            ...csvData.map(row => row.join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `leads_${format(new Date(), 'dd-MM-yyyy')}.csv`;
        link.click();
    };

    if (loading) {
        return (
            <DashboardLayout>
                <div className="flex justify-center items-center h-64">
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
                        Gerenciar Leads
                    </h1>
                </div>

                <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                    <div className="py-4">
                        {/* Filtros e Busca */}
                        <div className="flex flex-col sm:flex-row justify-between items-center mb-6 space-y-4 sm:space-y-0">
                            <div className="flex items-center space-x-4">
                                <select
                                    value={filter}
                                    onChange={(e) => setFilter(e.target.value)}
                                    className="rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                                >
                                    <option value="all">Todos</option>
                                    <option value="client">Clientes</option>
                                    <option value="consultant">Consultores</option>
                                </select>

                                <input
                                    type="text"
                                    placeholder="Buscar..."
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    className="rounded-md bg-[#2a2a2a] border-gray-600 text-gray-300 focus:border-orange-500 focus:ring-orange-500"
                                />
                            </div>

                            <button
                                onClick={exportToCSV}
                                className="px-4 py-2 bg-orange-600 text-white rounded-md hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500"
                            >
                                Exportar CSV
                            </button>
                        </div>

                        {/* Lista de Leads */}
                        <div className="bg-[#1a1a1a] shadow overflow-hidden sm:rounded-md">
                            {error ? (
                                <p className="text-red-400 p-4">{error}</p>
                            ) : filteredLeads.length === 0 ? (
                                <p className="text-gray-400 p-4">Nenhum lead encontrado</p>
                            ) : (
                                <ul className="divide-y divide-gray-700">
                                    {filteredLeads.map((lead) => (
                                        <li key={lead.id} className="px-6 py-4">
                                            <div className="flex items-center justify-between">
                                                <div>
                                                    <h3 className="text-lg font-medium text-gray-200">
                                                        {lead.name}
                                                    </h3>
                                                    <div className="mt-1 text-sm text-gray-400">
                                                        <p>Email: {lead.email}</p>
                                                        <p>Telefone: {lead.phone}</p>
                                                    </div>
                                                </div>
                                                <div className="text-right">
                                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                                        lead.type === 'client' 
                                                            ? 'bg-green-100 text-green-800' 
                                                            : 'bg-blue-100 text-blue-800'
                                                    }`}>
                                                        {lead.type === 'client' ? 'Cliente' : 'Consultor'}
                                                    </span>
                                                    <p className="mt-1 text-sm text-gray-400">
                                                        {format(
                                                            new Date(lead.created_at),
                                                            "dd 'de' MMMM', às' HH:mm",
                                                            { locale: ptBR }
                                                        )}
                                                    </p>
                                                </div>
                                            </div>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </DashboardLayout>
    );
};

export default Leads; 