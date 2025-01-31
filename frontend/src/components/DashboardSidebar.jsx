import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import useProductAccess from '../hooks/useProductAccess';
import defaultAvatar from '../assets/images/default-avatar.png';
import {
    HomeIcon,
    AcademicCapIcon,
    MagnifyingGlassIcon,
    Cog6ToothIcon,
    UserGroupIcon,
    BookOpenIcon,
    ArrowRightOnRectangleIcon,
    DocumentDuplicateIcon,
    RocketLaunchIcon
} from '@heroicons/react/24/outline';

const DashboardSidebar = () => {
    const location = useLocation();
    const { user, logout } = useAuth();
    const isAdmin = user?.role === 'admin';
    const { hasAccess: hasLandpageAccess, loading } = useProductAccess('landpage');

    const handleLogout = async () => {
        try {
            await logout();
        } catch (error) {
            console.error('Erro ao fazer logout:', error);
        }
    };

    const menuItems = [
        {
            title: 'Dashboard',
            path: '/dashboard',
            icon: <HomeIcon className="w-6 h-6" />
        },
        {
            title: 'Explorar',
            path: '/dashboard/explore',
            icon: <RocketLaunchIcon className="w-6 h-6" />
        },
        {
            title: 'Meus Treinamentos',
            path: '/dashboard/trainings',
            icon: <AcademicCapIcon className="w-6 h-6" />
        }
    ];

    // Adiciona os itens de landpage apenas se o usuário tiver acesso
    if (hasLandpageAccess) {
        menuItems.push(
            {
                title: 'Landing Pages',
                path: '/dashboard/landpage',
                icon: <DocumentDuplicateIcon className="w-6 h-6" />
            },
            {
                title: 'Leads',
                path: '/dashboard/leads',
                icon: <UserGroupIcon className="w-6 h-6" />
            }
        );
    }

    const isActive = (path) => location.pathname === path;

    if (loading) {
        return <div className="p-4">Carregando...</div>;
    }

    return (
        <div className="flex grow flex-col gap-y-5 overflow-y-auto bg-black/50 backdrop-blur-sm px-6 pb-4">
            <div className="flex h-16 shrink-0 items-center">
                <Link to="/dashboard" className="text-2xl font-bold text-white">
                    LEX
                </Link>
            </div>
            <nav className="flex flex-1 flex-col">
                <ul role="list" className="flex flex-1 flex-col gap-y-7">
                    <li>
                        <ul role="list" className="-mx-2 space-y-1">
                            {menuItems.map((item) => (
                                <li key={item.path}>
                                    <Link
                                        to={item.path}
                                        className={`
                                            group flex gap-x-3 rounded-md p-2 text-sm font-semibold leading-6
                                            ${isActive(item.path)
                                                ? 'bg-orange-500 text-white'
                                                : 'text-gray-400 hover:text-white hover:bg-white/10'
                                            }
                                        `}
                                    >
                                        <div className={`
                                            mr-3 flex-shrink-0
                                            ${isActive(item.path)
                                                ? 'text-white'
                                                : 'text-gray-400 group-hover:text-gray-300'
                                            }
                                        `}>
                                            {item.icon}
                                        </div>
                                        {item.title}
                                    </Link>
                                </li>
                            ))}
                        </ul>
                    </li>

                    {/* Profile and Logout */}
                    <li className="-mx-2 mt-auto space-y-1">
                        <div className="flex items-center gap-x-4 px-2 py-3 text-sm font-semibold leading-6 text-gray-400">
                            <img
                                className="h-8 w-8 rounded-full bg-gray-800"
                                src={user?.avatar || defaultAvatar}
                                alt=""
                            />
                            <span className="sr-only sm:not-sr-only">{user?.name}</span>
                        </div>
                        <button
                            onClick={handleLogout}
                            className="flex w-full items-center gap-x-3 rounded-md p-2 text-sm font-semibold leading-6 text-gray-400 hover:text-white hover:bg-white/10"
                        >
                            <ArrowRightOnRectangleIcon className="h-6 w-6 shrink-0" aria-hidden="true" />
                            Sair
                        </button>
                    </li>
                </ul>
            </nav>
        </div>
    );
};

export default DashboardSidebar; 