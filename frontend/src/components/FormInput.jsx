import React from 'react';
import { ExclamationCircleIcon } from '@heroicons/react/24/solid';

const FormInput = ({ 
    id, 
    label, 
    type = 'text', 
    value, 
    onChange, 
    icon: Icon, 
    required = false,
    error = null 
}) => {
    return (
        <div>
            <label htmlFor={id} className="block text-sm font-medium text-gray-700">
                {label}
            </label>
            <div className="mt-1 relative rounded-md shadow-sm">
                {Icon && (
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Icon className="h-5 w-5 text-gray-400" aria-hidden="true" />
                    </div>
                )}
                <input
                    type={type}
                    id={id}
                    value={value}
                    onChange={onChange}
                    required={required}
                    className={`
                        block w-full 
                        ${Icon ? 'pl-10' : 'pl-3'} 
                        pr-3 py-2 
                        border border-gray-300 
                        rounded-md 
                        shadow-sm 
                        placeholder-gray-400 
                        focus:outline-none 
                        focus:ring-blue-500 
                        focus:border-blue-500 
                        sm:text-sm
                        ${error ? 'border-red-300' : ''}
                    `}
                />
                {error && (
                    <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                        <ExclamationCircleIcon className="h-5 w-5 text-red-500" aria-hidden="true" />
                    </div>
                )}
            </div>
            {error && (
                <p className="mt-2 text-sm text-red-600">{error}</p>
            )}
        </div>
    );
};

export default FormInput; 