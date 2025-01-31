import { useState } from 'react';
import { StarIcon } from '@heroicons/react/24/solid';
import { StarIcon as StarOutlineIcon } from '@heroicons/react/24/solid';
import api from '../services/api';

const CourseReview = ({ courseId, onReviewSubmitted }) => {
  const [rating, setRating] = useState(0);
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);

    try {
      await api.post(`/courses/${courseId}/reviews`, {
        rating,
        comment
      });
      setRating(0);
      setComment('');
      onReviewSubmitted();
    } catch (error) {
      console.error('Erro ao enviar avaliação:', error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm p-6">
      <h3 className="text-lg font-semibold mb-4">Avaliar este curso</h3>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <div className="flex items-center space-x-1">
            {[1, 2, 3, 4, 5].map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setRating(value)}
                className="focus:outline-none"
              >
                {value <= rating ? (
                  <StarIcon className="h-8 w-8 text-yellow-400" />
                ) : (
                  <StarOutlineIcon className="h-8 w-8 text-yellow-400" />
                )}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label htmlFor="comment" className="block text-sm font-medium text-gray-700">
            Seu comentário
          </label>
          <textarea
            id="comment"
            rows={4}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
            placeholder="Conte sua experiência com o curso..."
          />
        </div>

        <button
          type="submit"
          disabled={submitting || rating === 0}
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? 'Enviando...' : 'Enviar avaliação'}
        </button>
      </form>
    </div>
  );
};

export default CourseReview;
