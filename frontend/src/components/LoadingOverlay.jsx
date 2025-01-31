const LoadingOverlay = ({ message = 'Carregando...' }) => {
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900 bg-opacity-75">
            <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500 mx-auto"></div>
                <p className="mt-4 text-gray-200">{message}</p>
            </div>
        </div>
    );
};

export default LoadingOverlay; 