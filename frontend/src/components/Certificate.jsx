import { useState } from 'react';
import { 
    AcademicCapIcon,
    ArrowDownTrayIcon,
    CheckBadgeIcon,
    ShareIcon
} from '@heroicons/react/24/outline';
import api from '../services/api';

const Certificate = ({ courseId, courseName, completionDate }) => {
  const [loading, setLoading] = useState(false);

  const downloadCertificate = async () => {
    setLoading(true);
    try {
      const response = await api.get(`/courses/${courseId}/certificate`, {
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `certificado-${courseName}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('Erro ao baixar certificado:', error);
    } finally {
      setLoading(false);
    }
  };

  const shareCertificate = async () => {
    try {
      const shareData = {
        title: 'Meu Certificado',
        text: `Concluí o curso ${courseName} na plataforma LEX!`,
        url: `${window.location.origin}/certificates/${courseId}`
      };
      await navigator.share(shareData);
    } catch (error) {
      console.error('Erro ao compartilhar:', error);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm p-6">
      <div className="text-center">
        <h3 className="text-lg font-semibold mb-2">Certificado de Conclusão</h3>
        <p className="text-sm text-gray-600 mb-4">
          Parabéns por concluir o curso {courseName}!
        </p>
        <p className="text-xs text-gray-500 mb-6">
          Concluído em {new Date(completionDate).toLocaleDateString()}
        </p>
        
        <div className="flex justify-center space-x-4">
          <button
            onClick={downloadCertificate}
            disabled={loading}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <ArrowDownTrayIcon className="h-5 w-5 mr-2" />
            {loading ? 'Baixando...' : 'Baixar PDF'}
          </button>
          
          <button
            onClick={shareCertificate}
            className="flex items-center px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <ShareIcon className="h-5 w-5 mr-2" />
            Compartilhar
          </button>
        </div>
      </div>
    </div>
  );
};

export default Certificate; 