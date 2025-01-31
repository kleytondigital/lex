import { Fragment } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Disclosure, Menu, Transition } from '@headlessui/react';
import { 
    MagnifyingGlassIcon, 
    BellIcon,
    Bars3Icon,
    XMarkIcon 
} from '@heroicons/react/24/outline';

import { useAuth } from '../hooks/useAuth.jsx';

const Layout = ({ children }) => {
    const { user, logout } = useAuth();
    const location = useLocation();

    return (
        <div className="min-h-screen bg-[#141414]">
            {/* Sidebar */}
            <div className="fixed inset-y-0 left-0 w-64 bg-[#1a1a1a] shadow-xl">
                <div className="flex flex-col h-full">
                    {/* Logo */}
                    <div className="flex items-center h-16 px-6 bg-[#1a1a1a]">
                        <Link to="/" className="flex-shrink-0">
                            <img
                                className="h-8 w-auto"
                                src="/src/assets/logo.png"
                                alt="LEX"
                            />
                        </Link>
                    </div>

                    {/* Navigation */}
                    <nav className="flex-1 px-3 py-6 space-y-1.5">
                        <Link
                            to="/"
                            className={`${
                                location.pathname === '/'
                                    ? 'bg-orange-500/20 text-orange-500'
                                    : 'text-gray-400 hover:bg-orange-500/10 hover:text-orange-500'
                            } group flex items-center px-4 py-2.5 text-sm font-medium rounded-lg transition-all duration-200`}
                        >
                            <span className="truncate">Início</span>
                        </Link>
                        <Link
                            to="/courses"
                            className={`${
                                location.pathname === '/courses'
                                    ? 'bg-orange-500/20 text-orange-500'
                                    : 'text-gray-400 hover:bg-orange-500/10 hover:text-orange-500'
                            } group flex items-center px-4 py-2.5 text-sm font-medium rounded-lg transition-all duration-200`}
                        >
                            <span className="truncate">Cursos</span>
                        </Link>
                        <Link
                            to="/my-courses"
                            className={`${
                                location.pathname === '/my-courses'
                                    ? 'bg-orange-500/20 text-orange-500'
                                    : 'text-gray-400 hover:bg-orange-500/10 hover:text-orange-500'
                            } group flex items-center px-4 py-2.5 text-sm font-medium rounded-lg transition-all duration-200`}
                        >
                            <span className="truncate">Meus Cursos</span>
                        </Link>
                    </nav>

                    {/* User Profile */}
                    <div className="p-4">
                        <Menu as="div" className="relative">
                            <Menu.Button className="w-full flex items-center space-x-3 hover:bg-[#252525] p-3 rounded-lg transition-all duration-200">
                                <img
                                    className="h-10 w-10 rounded-lg object-cover"
                                    src={user?.avatar || '/default-avatar.png'}
                                    alt=""
                                />
                                <div className="flex-1 text-left">
                                    <p className="text-sm font-medium text-gray-200 truncate">
                                        {user?.name}
                                    </p>
                                    <p className="text-xs text-gray-500 truncate">
                                        {user?.email}
                                    </p>
                                </div>
                            </Menu.Button>
                            <Transition
                                as={Fragment}
                                enter="transition ease-out duration-100"
                                enterFrom="transform opacity-0 scale-95"
                                enterTo="transform opacity-100 scale-100"
                                leave="transition ease-in duration-75"
                                leaveFrom="transform opacity-100 scale-100"
                                leaveTo="transform opacity-0 scale-95"
                            >
                                <Menu.Items className="absolute bottom-full left-0 w-48 mb-2 rounded-lg shadow-lg py-1 bg-[#252525] ring-1 ring-black ring-opacity-5 focus:outline-none">
                                    <Menu.Item>
                                        <Link
                                            to="/profile"
                                            className="block px-4 py-2 text-sm text-gray-300 hover:bg-[#303030] transition-colors duration-150"
                                        >
                                            Meu Perfil
                                        </Link>
                                    </Menu.Item>
                                    <Menu.Item>
                                        <button
                                            onClick={logout}
                                            className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-[#303030] transition-colors duration-150"
                                        >
                                            Sair
                                        </button>
                                    </Menu.Item>
                                </Menu.Items>
                            </Transition>
                        </Menu>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="pl-64">
                {/* Top Bar */}
                <div className="bg-[#1a1a1a] shadow-md">
                    <div className="flex items-center justify-between h-16 px-6">
                        <div className="flex-1 flex justify-end">
                            <div className="max-w-lg w-full max-w-xs">
                                <div className="relative">
                                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                        <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
                                    </div>
                                    <input
                                        type="search"
                                        className="block w-full pl-10 pr-3 py-2 border border-transparent rounded-lg text-sm bg-[#252525] text-gray-300 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all duration-150"
                                        placeholder="Buscar cursos..."
                                    />
                                </div>
                            </div>
                            <button className="ml-4 p-2 rounded-lg text-gray-400 hover:text-orange-500 hover:bg-[#252525] transition-all duration-150">
                                <BellIcon className="h-6 w-6" aria-hidden="true" />
                            </button>
                        </div>
                    </div>
                </div>

                {/* Page Content */}
                <main className="py-8">
                    <div className="max-w-7xl mx-auto px-6">
                        {children}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default Layout; 