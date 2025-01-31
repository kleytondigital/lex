import { XMarkIcon } from '@heroicons/react/24/solid';

export default function Notification({ message, type = 'success', onClose }) {
    return (
        <div className={`rounded-md p-4 ${type === 'success' ? 'bg-green-50' : 'bg-red-50'}`}>
            <div className="flex">
                <div className="flex-1">
                    <p className={`text-sm font-medium ${type === 'success' ? 'text-green-800' : 'text-red-800'}`}>
                        {message}
                    </p>
                </div>
                <div className="ml-3">
                    <button
                        type="button"
                        onClick={onClose}
                        className={`inline-flex rounded-md p-1.5 ${
                            type === 'success'
                                ? 'bg-green-50 text-green-500 hover:bg-green-100'
                                : 'bg-red-50 text-red-500 hover:bg-red-100'
                        }`}
                    >
                        <span className="sr-only">Fechar</span>
                        <XMarkIcon className="h-5 w-5" aria-hidden="true" />
                    </button>
                </div>
            </div>
        </div>
    );
}
