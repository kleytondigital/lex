import { ExclamationTriangleIcon } from '@heroicons/react/24/outline';

const ConfirmationModal = ({ isOpen, onClose, onConfirm, title, message, confirmText = 'Confirmar', cancelText = 'Cancelar', type = 'danger' }) => {
    if (!isOpen) return null;

    const colorClasses = {
        danger: {
            icon: 'text-red-400',
            button: 'bg-red-500 hover:bg-red-600 focus:ring-red-500'
        },
        warning: {
            icon: 'text-yellow-400',
            button: 'bg-yellow-500 hover:bg-yellow-600 focus:ring-yellow-500'
        },
        info: {
            icon: 'text-blue-400',
            button: 'bg-blue-500 hover:bg-blue-600 focus:ring-blue-500'
        }
    };

    const colors = colorClasses[type];

    return (
        <div className="fixed inset-0 z-50 overflow-y-auto">
            <div className="flex min-h-screen items-end justify-center px-4 pt-4 pb-20 text-center sm:block sm:p-0">
                <div className="fixed inset-0 bg-gray-900 bg-opacity-75 transition-opacity" onClick={onClose} />

                <span className="hidden sm:inline-block sm:h-screen sm:align-middle">&#8203;</span>

                <div className="inline-block transform overflow-hidden rounded-lg bg-gray-800 text-left align-bottom shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg sm:align-middle">
                    <div className="bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                        <div className="sm:flex sm:items-start">
                            <div className={`mx-auto flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-gray-700 sm:mx-0 sm:h-10 sm:w-10`}>
                                <ExclamationTriangleIcon className={`h-6 w-6 ${colors.icon}`} aria-hidden="true" />
                            </div>
                            <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                                <h3 className="text-lg font-medium leading-6 text-gray-200">
                                    {title}
                                </h3>
                                <div className="mt-2">
                                    <p className="text-sm text-gray-400">
                                        {message}
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="bg-gray-700 px-4 py-3 sm:flex sm:flex-row-reverse sm:px-6">
                        <button
                            type="button"
                            className={`inline-flex w-full justify-center rounded-md border border-transparent px-4 py-2 text-base font-medium text-white shadow-sm focus:outline-none focus:ring-2 focus:ring-offset-2 sm:ml-3 sm:w-auto sm:text-sm ${colors.button}`}
                            onClick={onConfirm}
                        >
                            {confirmText}
                        </button>
                        <button
                            type="button"
                            className="mt-3 inline-flex w-full justify-center rounded-md border border-gray-600 bg-gray-800 px-4 py-2 text-base font-medium text-gray-400 shadow-sm hover:text-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                            onClick={onClose}
                        >
                            {cancelText}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ConfirmationModal; 