import { Fragment, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Dialog, Transition } from '@headlessui/react';
import { Bars3Icon, XMarkIcon } from '@heroicons/react/24/outline';
import DashboardSidebar from './DashboardSidebar';
import { useAuth } from '../hooks/useAuth';
import defaultAvatar from '../assets/images/default-avatar.png';

const DashboardLayout = () => {
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const { user } = useAuth();

    return (
        <div className="min-h-screen bg-[#141414]">
            {/* Mobile sidebar */}
            <Transition.Root show={sidebarOpen} as={Fragment}>
                <Dialog as="div" className="relative z-50 lg:hidden" onClose={setSidebarOpen}>
                    <Transition.Child
                        as={Fragment}
                        enter="transition-opacity ease-linear duration-300"
                        enterFrom="opacity-0"
                        enterTo="opacity-100"
                        leave="transition-opacity ease-linear duration-300"
                        leaveFrom="opacity-100"
                        leaveTo="opacity-0"
                    >
                        <div className="fixed inset-0 bg-gray-900/80" />
                    </Transition.Child>

                    <div className="fixed inset-0 flex">
                        <Transition.Child
                            as={Fragment}
                            enter="transition ease-in-out duration-300 transform"
                            enterFrom="-translate-x-full"
                            enterTo="translate-x-0"
                            leave="transition ease-in-out duration-300 transform"
                            leaveFrom="translate-x-0"
                            leaveTo="-translate-x-full"
                        >
                            <Dialog.Panel className="relative mr-16 flex w-full max-w-xs flex-1">
                                <DashboardSidebar />
                            </Dialog.Panel>
                        </Transition.Child>
                    </div>
                </Dialog>
            </Transition.Root>

            {/* Static sidebar for desktop */}
            <div className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-72">
                <DashboardSidebar />
            </div>

            {/* Main content */}
            <div className="lg:pl-72">
                {/* Top bar */}
                <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 bg-[#141414]/80 backdrop-blur-sm px-4 sm:gap-x-6 sm:px-6 lg:px-8">
                    <button
                        type="button"
                        className="-m-2.5 p-2.5 text-gray-400 lg:hidden"
                        onClick={() => setSidebarOpen(true)}
                    >
                        <span className="sr-only">Abrir menu</span>
                        <Bars3Icon className="h-6 w-6" aria-hidden="true" />
                    </button>

                    {/* Separator */}
                    <div className="h-6 w-px bg-gray-700 lg:hidden" aria-hidden="true" />

                    <div className="flex flex-1 justify-end gap-x-4 self-stretch lg:gap-x-6">
                        <div className="flex items-center gap-x-4 lg:gap-x-6">
                            {/* Profile dropdown */}
                            <div className="relative">
                                <button
                                    type="button"
                                    className="flex items-center gap-x-3 text-sm font-semibold leading-6 text-gray-200"
                                >
                                    <span className="sr-only">Abrir menu do usuário</span>
                                    <img
                                        className="h-8 w-8 rounded-full bg-gray-800"
                                        src={user?.avatar || defaultAvatar}
                                        alt=""
                                    />
                                    <span className="hidden lg:flex">{user?.name}</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Main content area */}
                <main>
                    <Outlet />
                </main>
            </div>
        </div>
    );
};

export default DashboardLayout;
