import { useState, useRef } from 'react';
import api from '../../services/api';

const ImageUpload = ({ currentImage, onUploadSuccess }) => {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [preview, setPreview] = useState(currentImage);
    const fileInputRef = useRef();

    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        if (!file) return;

        if (!file.type.startsWith('image/')) {
            setError('Por favor, selecione uma imagem válida');
            return;
        }

        if (file.size > 5 * 1024 * 1024) { // 5MB
            setError('A imagem deve ter no máximo 5MB');
            return;
        }

        setError('');
        handleUpload(file);
        
        // Preview local
        const reader = new FileReader();
        reader.onloadend = () => {
            setPreview(reader.result);
        };
        reader.readAsDataURL(file);
    };

    const handleUpload = async (file) => {
        setLoading(true);
        const formData = new FormData();
        formData.append('photo', file);

        try {
            const { data } = await api.post('/landpage/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });

            onUploadSuccess(data.photoUrl);
            setError('');
        } catch (error) {
            setError(error.response?.data?.error || 'Erro ao fazer upload da imagem');
            setPreview(currentImage);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="space-y-4">
            <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                    Sua Foto
                </label>
                
                <div className="flex items-center space-x-6">
                    {preview && (
                        <div className="w-24 h-24 rounded-full overflow-hidden bg-gray-800">
                            <img
                                src={preview}
                                alt="Preview"
                                className="w-full h-full object-cover"
                            />
                        </div>
                    )}

                    <div>
                        <input
                            type="file"
                            ref={fileInputRef}
                            onChange={handleFileSelect}
                            accept="image/*"
                            className="hidden"
                        />
                        <button
                            type="button"
                            onClick={() => fileInputRef.current.click()}
                            disabled={loading}
                            className="px-4 py-2 bg-gray-700 text-white rounded-md hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 disabled:opacity-50"
                        >
                            {loading ? 'Enviando...' : 'Escolher Foto'}
                        </button>
                        <p className="mt-1 text-sm text-gray-400">
                            JPG, PNG ou GIF até 5MB
                        </p>
                    </div>
                </div>
            </div>

            {error && (
                <p className="text-red-400 text-sm">{error}</p>
            )}
        </div>
    );
};

export default ImageUpload; 