import { Fragment } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Menu, Transition } from '@headlessui/react';
import {
    HomeIcon,
    UsersIcon,
    AcademicCapIcon,
    UserGroupIcon,
    TagIcon,
    ShoppingBagIcon,
    ChartBarIcon,
    DocumentChartBarIcon,
    TicketIcon,
    GlobeAltIcon,
    DocumentIcon,
    UserCircleIcon,
    CogIcon,
    ArrowRightOnRectangleIcon,
    ChatBubbleLeftRightIcon,
    SparklesIcon,
    WrenchScrewdriverIcon
} from '@heroicons/react/24/outline';

import { useAuth } from '../hooks/useAuth';

const navigation = [
    { name: 'Dashboard', href: '/admin/dashboard', icon: HomeIcon },
    {
        name: 'Gerenciamento',
        children: [
            { name: 'Usuários', href: '/admin/users', icon: UsersIcon },
            { name: 'Treinamentos', href: '/admin/trainings', icon: AcademicCapIcon },
            { name: 'Instrutores', href: '/admin/instructors', icon: UserGroupIcon },
            { name: 'Categorias', href: '/admin/categories', icon: TagIcon },
        ],
    },
    {
        name: 'Produtos',
        children: [
            { name: 'Catálogo', href: '/admin/products', icon: ShoppingBagIcon },
            { name: 'Vendas', href: '/admin/sales', icon: ChartBarIcon },
            { name: 'Relatórios', href: '/admin/reports', icon: DocumentChartBarIcon },
            { name: 'Cupons', href: '/admin/coupons', icon: TicketIcon },
        ],
    },
    {
        name: 'Landing Pages',
        children: [
            { name: 'Todas as Pages', href: '/admin/landpages', icon: GlobeAltIcon },
            { name: 'Templates', href: '/admin/landpages/templates', icon: DocumentIcon },
            { name: 'Leads', href: '/admin/landpages/leads', icon: UserCircleIcon },
        ],
    },
    {
        name: 'IA',
        children: [
            { name: 'Agentes', href: '/admin/ai/agents', icon: SparklesIcon },
            { name: 'Configurações', href: '/admin/ai/settings', icon: WrenchScrewdriverIcon },
        ],
    },
    { name: 'Suporte', href: '/admin/support', icon: ChatBubbleLeftRightIcon },
    { name: 'Permissões', href: '/admin/roles', icon: CogIcon },
];

function classNames(...classes) {
    return classes.filter(Boolean).join(' ');
}

const AdminSidebar = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { logout } = useAuth();

    const handleLogout = () => {
        try {
            logout();
            navigate('/login');
        } catch (error) {
            console.error('Erro ao fazer logout:', error);
        }
    };

    const isActive = (href) => {
        return location.pathname === href;
    };

    return (
        <div className="hidden lg:fixed lg:inset-y-0 lg:flex lg:w-64 lg:flex-col bg-[#141414]">
            <div className="flex flex-col flex-grow pt-5 overflow-y-auto border-r border-gray-800">
                <div className="flex items-center flex-shrink-0 px-4">
                    <span className="text-2xl font-bold text-white">Alexandria</span>
                </div>
                <div className="mt-5 flex-grow flex flex-col">
                    <nav className="flex-1 px-2 space-y-1">
                        {navigation.map((item) =>
                            !item.children ? (
                                <div key={item.name}>
                                    <a
                                        href={item.href}
                                        onClick={(e) => {
                                            e.preventDefault();
                                            navigate(item.href);
                                        }}
                                        className={classNames(
                                            isActive(item.href)
                                                ? 'bg-gray-900 text-white'
                                                : 'text-gray-300 hover:bg-gray-800 hover:text-white',
                                            'group flex items-center px-2 py-2 text-sm font-medium rounded-md'
                                        )}
                                    >
                                        <item.icon
                                            className={classNames(
                                                isActive(item.href) ? 'text-orange-500' : 'text-gray-400 group-hover:text-gray-300',
                                                'mr-3 flex-shrink-0 h-6 w-6'
                                            )}
                                            aria-hidden="true"
                                        />
                                        {item.name}
                                    </a>
                                </div>
                            ) : (
                                <div key={item.name} className="space-y-1">
                                    <div className="px-3 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                        {item.name}
                                    </div>
                                    {item.children.map((subItem) => (
                                        <a
                                            key={subItem.name}
                                            href={subItem.href}
                                            onClick={(e) => {
                                                e.preventDefault();
                                                navigate(subItem.href);
                                            }}
                                            className={classNames(
                                                isActive(subItem.href)
                                                    ? 'bg-gray-900 text-white'
                                                    : 'text-gray-300 hover:bg-gray-800 hover:text-white',
                                                'group flex items-center px-2 py-2 text-sm font-medium rounded-md ml-2'
                                            )}
                                        >
                                            <subItem.icon
                                                className={classNames(
                                                    isActive(subItem.href) ? 'text-orange-500' : 'text-gray-400 group-hover:text-gray-300',
                                                    'mr-3 flex-shrink-0 h-6 w-6'
                                                )}
                                                aria-hidden="true"
                                            />
                                            {subItem.name}
                                        </a>
                                    ))}
                                </div>
                            )
                        )}
                    </nav>
                </div>
                <div className="flex-shrink-0 flex border-t border-gray-800 p-4">
                    <button
                        onClick={handleLogout}
                        className="flex-shrink-0 w-full group block text-gray-300 hover:text-white"
                    >
                        <div className="flex items-center">
                            <ArrowRightOnRectangleIcon className="inline-block h-6 w-6 mr-3 text-gray-400 group-hover:text-gray-300" />
                            <div className="text-sm font-medium">Sair</div>
                        </div>
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AdminSidebar; 