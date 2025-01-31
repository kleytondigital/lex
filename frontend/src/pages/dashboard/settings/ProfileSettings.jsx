import { useState, useEffect } from 'react';
import DashboardLayout from '../../../components/DashboardLayout';
import { useAuth } from '../../../hooks/useAuth';
import api from '../../../services/api';

const ProfileSettings = () => {
    const { user } = useAuth();
    const [loading, setLoading] = useState(false);
    const [formData, setFormData] = useState({
        name: user?.name || '',
        email: user?.email || '',
        avatar: user?.avatar || null
    });

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            await api.put('/user/profile', formData);
            // Atualizar contexto do usuário se necessário
        } catch (error) {
            console.error('Erro ao atualizar perfil:', error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <DashboardLayout>
            <div className="px-4 sm:px-6 lg:px-8">
                <h1 className="text-2xl font-semibold text-gray-200">Configurações do Perfil</h1>
                {/* Implementar formulário */}
            </div>
        </DashboardLayout>
    );
};

export default ProfileSettings; 