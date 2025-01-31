import { useState, useEffect } from 'react';
import { 
  ChartBarIcon, 
  ArrowTrendingUpIcon, // Substituído TrendingUpIcon por ArrowTrendingUpIcon
  UsersIcon, 
  CurrencyDollarIcon, 
  DocumentChartBarIcon, 
  ArrowDownTrayIcon, 
  FunnelIcon, 
  CalendarDaysIcon 
} from '@heroicons/react/24/outline';
import AdminLayout from '../../components/AdminLayout';
import api from '../../services/api';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const AdminReports = () => {
  const [period, setPeriod] = useState('month');
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
  }, [period]);

  const fetchMetrics = async () => {
    try {
      const response = await api.get(`/admin/reports/metrics?period=${period}`);
      setMetrics(response.data);
    } catch (error) {
      console.error('Erro ao carregar métricas:', error);
    } finally {
      setLoading(false);
    }
  };

  const data = [
    { name: 'Jan', vendas: 4000, alunos: 2400 },
    { name: 'Fev', vendas: 3000, alunos: 1398 },
    { name: 'Mar', vendas: 2000, alunos: 9800 },
    { name: 'Abr', vendas: 2780, alunos: 3908 },
    { name: 'Mai', vendas: 1890, alunos: 4800 },
    { name: 'Jun', vendas: 2390, alunos: 3800 },
  ];

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* Cards de Métricas */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-[#1a1a1a] p-6 rounded-lg shadow-lg">
            <h3 className="text-gray-400 text-sm font-medium">Vendas Totais</h3>
            <p className="text-2xl font-bold text-gray-200 mt-2">R$ {metrics && metrics.revenue ? metrics.revenue.toLocaleString() : '0'}</p>
            <span className="text-green-500 text-sm">+{metrics?.revenueGrowth}% este mês</span>
          </div>
          <div className="bg-[#1a1a1a] p-6 rounded-lg shadow-lg">
            <h3 className="text-gray-400 text-sm font-medium">Novos Alunos</h3>
            <p className="text-2xl font-bold text-gray-200 mt-2">{metrics && metrics.newUsers ? metrics.newUsers : 0}</p>
            <span className="text-green-500 text-sm">+{metrics?.userGrowth}% este mês</span>
          </div>
          <div className="bg-[#1a1a1a] p-6 rounded-lg shadow-lg">
            <h3 className="text-gray-400 text-sm font-medium">Taxa de Conclusão</h3>
            <p className="text-2xl font-bold text-gray-200 mt-2">{metrics && metrics.completionRate ? metrics.completionRate : 0}%</p>
            <span className="text-red-500 text-sm">-3% este mês</span>
          </div>
          <div className="bg-[#1a1a1a] p-6 rounded-lg shadow-lg">
            <h3 className="text-gray-400 text-sm font-medium">Avaliação Média</h3>
            <p className="text-2xl font-bold text-gray-200 mt-2">{metrics && metrics.rating ? metrics.rating : 0}</p>
            <span className="text-green-500 text-sm">+0.2 este mês</span>
          </div>
        </div>

        {/* Gráfico */}
        <div className="bg-[#1a1a1a] p-6 rounded-lg shadow-lg">
          <h3 className="text-gray-200 text-lg font-medium mb-6">Desempenho</h3>
          <div className="h-80">
            <Line
              data={{
                labels: data.map(d => d.name),
                datasets: [
                  {
                    label: 'Vendas',
                    data: data.map(d => d.vendas),
                    borderColor: '#f97316',
                    tension: 0.4
                  },
                  {
                    label: 'Alunos',
                    data: data.map(d => d.alunos),
                    borderColor: '#3b82f6',
                    tension: 0.4
                  }
                ]
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: {
                    grid: {
                      color: '#333'
                    },
                    ticks: {
                      color: '#666'
                    }
                  },
                  x: {
                    grid: {
                      color: '#333'
                    },
                    ticks: {
                      color: '#666'
                    }
                  }
                },
                plugins: {
                  legend: {
                    labels: {
                      color: '#666'
                    }
                  }
                }
              }}
            />
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminReports;
