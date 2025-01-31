import { useState, useEffect } from 'react';
import { 
    UsersIcon, 
    ChartBarSquareIcon,
    GlobeAltIcon, 
    ArrowTrendingUpIcon 
} from '@heroicons/react/24/outline';
import api from '../../services/api';

const Stats = () => {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        loadStats();
    }, []);

    const loadStats = async () => {
        try {
            const { data } = await api.get('/users/stats');
            setStats(data);
        } catch (error) {
            setError('Erro ao carregar estatísticas');
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
                {[...Array(4)].map((_, i) => (
                    <div 
                        key={i}
                        className="bg-[#1a1a1a] overflow-hidden shadow rounded-lg animate-pulse"
                    >
                        <div className="p-5">
                            <div className="flex items-center">
                                <div className="w-12 h-12 bg-gray-700 rounded-md"></div>
                                <div className="ml-5 w-full">
                                    <div className="h-4 bg-gray-700 rounded w-1/2"></div>
                                    <div className="mt-2 h-8 bg-gray-700 rounded w-3/4"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        );
    }

    const statItems = [
        {
            name: 'Leads de Clientes',
            value: stats?.leads.clients || 0,
            icon: UsersIcon,
            color: 'text-green-500'
        },
        {
            name: 'Leads de Consultores',
            value: stats?.leads.consultants || 0,
            icon: ChartBarSquareIcon,
            color: 'text-blue-500'
        },
        {
            name: 'Landing Pages Ativas',
            value: stats?.activeLandpages || 0,
            icon: GlobeAltIcon,
            color: 'text-purple-500'
        },
        {
            name: 'Taxa de Conversão',
            value: `${((stats?.conversions / (stats?.leads.clients + stats?.leads.consultants)) * 100 || 0).toFixed(1)}%`,
            icon: ArrowTrendingUpIcon,
            color: 'text-orange-500'
        }
    ];

    return (
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {error ? (
                <div className="col-span-full text-red-400 text-center">
                    {error}
                </div>
            ) : (
                statItems.map((item) => (
                    <div
                        key={item.name}
                        className="bg-[#1a1a1a] overflow-hidden shadow rounded-lg hover:bg-[#222] transition-colors"
                    >
                        <div className="p-5">
                            <div className="flex items-center">
                                <div className="flex-shrink-0">
                                    <item.icon
                                        className={`h-12 w-12 ${item.color}`}
                                        aria-hidden="true"
                                    />
                                </div>
                                <div className="ml-5 w-0 flex-1">
                                    <dl>
                                        <dt className="text-sm font-medium text-gray-400 truncate">
                                            {item.name}
                                        </dt>
                                        <dd className="text-2xl font-semibold text-gray-200">
                                            {item.value}
                                        </dd>
                                    </dl>
                                </div>
                            </div>
                        </div>
                    </div>
                ))
            )}
        </div>
    );
};

export default Stats; 