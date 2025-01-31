import { useState } from 'react';
import AdminLayout from '../../components/AdminLayout';
import {
    Cog6ToothIcon,
    BellIcon,
    ShieldCheckIcon,
    KeyIcon,
    DocumentTextIcon,
    PaintBrushIcon
} from '@heroicons/react/24/outline';

const AdminSettings = () => {
    const [settings, setSettings] = useState({
        siteName: 'LEX Treinamentos',
        allowRegistration: true,
        requireEmailVerification: true,
        maintenanceMode: false,
        smtp: {
            host: 'smtp.example.com',
            port: '587',
            user: 'noreply@example.com',
            password: ''
        },
        payment: {
            provider: 'stripe',
            testMode: true,
            apiKey: '',
            secretKey: ''
        }
    });

    const handleSubmit = (e) => {
        e.preventDefault();
        // Implementar lógica de salvamento
    };

    return (
        <AdminLayout>
            <div className="max-w-4xl mx-auto">
                <h1 className="text-2xl font-semibold mb-6">Configurações do Sistema</h1>
                <div className="bg-white rounded-lg shadow">
                    <div className="p-6">
                        <div className="max-w-3xl">
                            <div className="space-y-6">
                                {/* Configurações Gerais */}
                                <div>
                                    <h3 className="text-lg font-medium mb-4">Configurações Gerais</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Nome do Site
                                            </label>
                                            <input
                                                type="text"
                                                value={settings.siteName}
                                                onChange={(e) => setSettings({ ...settings, siteName: e.target.value })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Email de Contato
                                            </label>
                                            <input
                                                type="email"
                                                className="w-full px-4 py-2 border rounded-lg"
                                                defaultValue="contato@lextreinamentos.com"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Configurações de Email */}
                                <div>
                                    <h3 className="text-lg font-medium mb-4">Configurações de Email</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Servidor SMTP
                                            </label>
                                            <input
                                                type="text"
                                                value={settings.smtp.host}
                                                onChange={(e) => setSettings({
                                                    ...settings,
                                                    smtp: { ...settings.smtp, host: e.target.value }
                                                })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Porta
                                            </label>
                                            <input
                                                type="text"
                                                value={settings.smtp.port}
                                                onChange={(e) => setSettings({
                                                    ...settings,
                                                    smtp: { ...settings.smtp, port: e.target.value }
                                                })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Usuário
                                            </label>
                                            <input
                                                type="text"
                                                value={settings.smtp.user}
                                                onChange={(e) => setSettings({
                                                    ...settings,
                                                    smtp: { ...settings.smtp, user: e.target.value }
                                                })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Senha
                                            </label>
                                            <input
                                                type="password"
                                                value={settings.smtp.password}
                                                onChange={(e) => setSettings({
                                                    ...settings,
                                                    smtp: { ...settings.smtp, password: e.target.value }
                                                })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* Configurações de Pagamento */}
                                <div>
                                    <h3 className="text-lg font-medium mb-4">Configurações de Pagamento</h3>
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Chave da API de Pagamento
                                            </label>
                                            <input
                                                type="password"
                                                value={settings.payment.apiKey}
                                                onChange={(e) => setSettings({
                                                    ...settings,
                                                    payment: { ...settings.payment, apiKey: e.target.value }
                                                })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">
                                                Moeda Padrão
                                            </label>
                                            <select
                                                value={settings.payment.provider}
                                                onChange={(e) => setSettings({
                                                    ...settings,
                                                    payment: { ...settings.payment, provider: e.target.value }
                                                })}
                                                className="w-full px-4 py-2 border rounded-lg"
                                            >
                                                <option value="stripe">Stripe</option>
                                                <option value="paypal">PayPal</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                {/* Botão de Salvar */}
                                <div className="pt-4">
                                    <button
                                        type="submit"
                                        className="bg-orange-500 text-white px-6 py-2 rounded-lg hover:bg-orange-600"
                                    >
                                        Salvar Alterações
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div className="settings-icons">
                <Cog6ToothIcon className="h-6 w-6" />
                <BellIcon className="h-6 w-6" />
                <ShieldCheckIcon className="h-6 w-6" />
                <KeyIcon className="h-6 w-6" />
                <DocumentTextIcon className="h-6 w-6" />
                <PaintBrushIcon className="h-6 w-6" />
            </div>
        </AdminLayout>
    );
};

export default AdminSettings; 