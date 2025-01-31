import { useEffect, useState } from 'react';
import { CheckCircleIcon } from '@heroicons/react/24/solid';
import { CheckCircleIcon as CheckCircleOutlineIcon } from '@heroicons/react/24/solid';
import api from '../services/api';

const CourseProgress = ({ courseId }) => {
  const [progress, setProgress] = useState({
    completed: 0,
    total: 0,
    lessons: {}
  });

  useEffect(() => {
    fetchProgress();
  }, [courseId]);

  const fetchProgress = async () => {
    try {
      const response = await api.get(`/courses/${courseId}/progress`);
      setProgress(response.data);
    } catch (error) {
      console.error('Erro ao carregar progresso:', error);
    }
  };

  const progressPercentage = Math.round((progress.completed / progress.total) * 100);

  return (
    <div className="bg-white rounded-lg shadow-sm p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Seu Progresso</h3>
        <span className="text-2xl font-bold text-blue-600">{progressPercentage}%</span>
      </div>

      <div className="w-full bg-gray-200 rounded-full h-2.5 mb-6">
        <div
          className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
          style={{ width: `${progressPercentage}%` }}
        ></div>
      </div>

      <div className="space-y-3">
        {Object.entries(progress.lessons).map(([lessonId, status]) => (
          <div key={lessonId} className="flex items-center justify-between">
            <span className="text-sm text-gray-600">{status.title}</span>
            {status.completed ? (
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
            ) : (
              <CheckCircleOutlineIcon className="h-5 w-5 text-gray-400" />
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default CourseProgress;
