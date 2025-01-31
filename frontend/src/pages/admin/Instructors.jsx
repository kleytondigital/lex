import { useState, useEffect } from 'react';
import AdminLayout from '../../components/AdminLayout';
import api from '../../services/api';
import {
    AcademicCapIcon,
    UserPlusIcon,
    PencilSquareIcon,
    TrashIcon,
    MagnifyingGlassIcon
} from '@heroicons/react/24/outline';

const AdminInstructors = () => {
    const [instructors, setInstructors] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchInstructors();
    }, []);

    const fetchInstructors = async () => {
        try {
            const response = await api.get('/admin/instructors');
            setInstructors(response.data);
        } catch (error) {
            console.error('Erro ao carregar instrutores:', error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <AdminLayout>
            <div className="bg-[#1a1a1a] rounded-lg shadow-lg p-6">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-semibold text-gray-200">Instrutores</h2>
                    <div className="instructor-actions">
                        <UserPlusIcon className="h-5 w-5 mr-2" />
                        <PencilSquareIcon className="h-5 w-5" />
                        <TrashIcon className="h-5 w-5" />
                    </div>
                </div>

                <div className="search-bar">
                    <MagnifyingGlassIcon className="h-5 w-5" />
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
                                    <th className="px-4 py-3 text-left text-sm font-medium rounded-l-lg">Nome</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Email</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Cursos</th>
                                    <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                                    <th className="px-4 py-3 text-right text-sm font-medium rounded-r-lg">Ações</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-[#252525]">
                                {instructors.map((instructor) => (
                                    <tr key={instructor.id} className="text-gray-300">
                                        <td className="px-4 py-4">
                                            <div className="flex items-center">
                                                <img
                                                    src={instructor.avatar || '/default-avatar.png'}
                                                    alt=""
                                                    className="h-8 w-8 rounded-lg object-cover mr-3"
                                                />
                                                <span className="font-medium">{instructor.name}</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-4 text-gray-400">{instructor.email}</td>
                                        <td className="px-4 py-4 text-gray-400">{instructor.coursesCount} cursos</td>
                                        <td className="px-4 py-4">
                                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                                                instructor.status === 'active'
                                                    ? 'bg-green-500/20 text-green-500'
                                                    : 'bg-gray-500/20 text-gray-500'
                                            }`}>
                                                {instructor.status === 'active' ? 'Ativo' : 'Inativo'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-4 text-right">
                                            <button className="text-gray-400 hover:text-orange-500 transition-colors">
                                                Editar
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

export default AdminInstructors; 