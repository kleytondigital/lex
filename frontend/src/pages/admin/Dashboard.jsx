import { useState, useEffect } from 'react';
import { UsersIcon, AcademicCapIcon, CurrencyDollarIcon, ChartBarSquareIcon } from '@heroicons/react/24/solid';
import api from '../../services/api';
import StatsCard from '../../components/admin/StatsCard';
import RecentUsers from '../../components/admin/RecentUsers';
import CoursesList from '../../components/admin/CoursesList';

const AdminDashboard = () => {
    const [stats, setStats] = useState({
        users: 0,
        courses: 0,
        activeUsers: 0,
        revenue: 0
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const response = await api.get('/admin/dashboard/stats');
                setStats(response.data);
            } catch (err) {
                console.error('Erro ao carregar estatísticas:', err);
                setError(err.response?.data?.message || 'Erro ao carregar estatísticas');
            } finally {
                setLoading(false);
            }
        };

        fetchStats();
    }, []);

    if (loading) {
        return (
            <div className="flex justify-center items-center h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex justify-center items-center h-screen">
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
                    <strong className="font-bold">Erro! </strong>
                    <span className="block sm:inline">{error}</span>
                </div>
            </div>
        );
    }

    return (
        <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                <h1 className="text-2xl font-semibold text-gray-900">Dashboard Administrativo</h1>
            </div>
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                {/* Cards de Estatísticas */}
                <div className="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
                    <StatsCard
                        title="Total de Usuários"
                        value={stats && stats.users ? stats.users : 0}
                        icon={UsersIcon}
                        change={stats && stats.usersChange ? stats.usersChange : "+0%"}
                        changeType="increase"
                    />
                    <StatsCard
                        title="Cursos Ativos"
                        value={stats && stats.courses ? stats.courses : 0}
                        icon={AcademicCapIcon}
                        change={stats && stats.coursesChange ? stats.coursesChange : "+0"}
                        changeType="increase"
                    />
                    <StatsCard
                        title="Usuários Ativos"
                        value={stats && stats.activeUsers ? stats.activeUsers : 0}
                        icon={ChartBarSquareIcon}
                        change={stats && stats.activeUsersChange ? stats.activeUsersChange : "+0%"}
                        changeType="increase"
                    />
                    <StatsCard
                        title="Receita Mensal"
                        value={`R$ ${stats && stats.revenue ? stats.revenue : 0}`}
                        icon={CurrencyDollarIcon}
                        change={stats && stats.revenueChange ? stats.revenueChange : "+0%"}
                        changeType="increase"
                    />
                </div>

                {/* Seção de Usuários Recentes e Cursos */}
                <div className="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-2">
                    <RecentUsers />
                    <CoursesList />
                </div>
            </div>
        </div>
    );
};

export default AdminDashboard;
