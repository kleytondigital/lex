import { useState, useEffect } from 'react';
import DashboardLayout from '../../../components/DashboardLayout';
import api from '../../../services/api';

const Leads = () => {
    const [leads, setLeads] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchLeads();
    }, []);

    const fetchLeads = async () => {
        try {
            const response = await api.get('/leads');
            setLeads(response.data);
        } catch (error) {
            console.error('Erro ao buscar leads:', error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <DashboardLayout>
            <div className="px-4 sm:px-6 lg:px-8">
                <h1 className="text-2xl font-semibold text-gray-200">Leads</h1>
                {/* Implementar lista de leads */}
            </div>
        </DashboardLayout>
    );
};

export default Leads; 