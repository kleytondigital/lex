import { 
    ArrowUpIcon,
    ArrowDownIcon 
} from '@heroicons/react/24/solid';

const StatsCard = ({ title, value, icon: Icon, change, changeType }) => {
    const formattedValue = typeof value === 'number' ? (value ? value.toLocaleString() : '0') : value;

    return (
        <div className="bg-[#1a1a1a] rounded-lg shadow-lg p-6">
            <div className="p-5">
                <div className="flex items-center">
                    <div className="flex-shrink-0">
                        <Icon className="h-6 w-6 text-gray-300" aria-hidden="true" />
                    </div>
                    <div className="ml-5 w-0 flex-1">
                        <dl>
                            <dt className="text-sm font-medium text-gray-400 truncate">{title}</dt>
                            <dd className="flex items-baseline">
                                <div className="text-2xl font-semibold text-gray-500">{formattedValue}</div>
                                <div className={`ml-2 flex items-baseline text-sm font-semibold ${
                                    changeType === 'increase' ? 'text-green-600' : 'text-red-600'
                                }`}>
                                    {change}
                                </div>
                            </dd>
                        </dl>
                    </div>
                </div>
                <div className="change-indicator">
                    {changeType === 'increase' ? (
                        <ArrowUpIcon className="h-4 w-4 text-green-500" />
                    ) : (
                        <ArrowDownIcon className="h-4 w-4 text-red-500" />
                    )}
                </div>
            </div>
        </div>
    );
};

export default StatsCard; 