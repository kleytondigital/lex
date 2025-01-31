import { useState } from 'react';
import { ChatBubbleLeftIcon, ArrowUturnLeftIcon } from '@heroicons/react/24/solid';
import api from '../services/api';

const CourseDiscussion = ({ courseId, lessonId }) => {
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [replyTo, setReplyTo] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await api.post(`/courses/${courseId}/lessons/${lessonId}/comments`, {
        content: newComment,
        parentId: replyTo
      });

      setComments([...comments, response.data]);
      setNewComment('');
      setReplyTo(null);
    } catch (error) {
      console.error('Erro ao enviar comentário:', error);
    } finally {
      setLoading(false);
    }
  };

  const Comment = ({ comment }) => (
    <div className={`${comment.parentId ? 'ml-8' : ''} mb-4`}>
      <div className="flex items-start space-x-3">
        <img
          src={comment.user.avatar}
          alt={comment.user.name}
          className="h-8 w-8 rounded-full"
        />
        <div className="flex-1">
          <div className="bg-gray-50 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <span className="font-medium text-sm">{comment.user.name}</span>
              <span className="text-xs text-gray-500">{comment.createdAt}</span>
            </div>
            <p className="text-sm text-gray-700 mt-1">{comment.content}</p>
          </div>
          <button
            onClick={() => setReplyTo(comment.id)}
            className="mt-1 text-sm text-gray-500 hover:text-gray-700 flex items-center"
          >
            <ArrowUturnLeftIcon className="h-4 w-4 mr-1" />
            Responder
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="bg-white rounded-lg shadow-sm p-6">
      <div className="flex items-center space-x-2 mb-6">
        <ChatBubbleLeftIcon  className="h-5 w-5 text-gray-400" />
        <h3 className="text-lg font-semibold">Discussão</h3>
      </div>

      <form onSubmit={handleSubmit} className="mb-6">
        <textarea
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          placeholder={replyTo ? "Escreva sua resposta..." : "Faça uma pergunta ou comentário..."}
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          rows={3}
        />
        <div className="flex items-center justify-between mt-2">
          {replyTo && (
            <button
              type="button"
              onClick={() => setReplyTo(null)}
              className="text-sm text-gray-500 hover:text-gray-700"
            >
              Cancelar resposta
            </button>
          )}
          <button
            type="submit"
            disabled={loading || !newComment.trim()}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Enviando...' : 'Enviar'}
          </button>
        </div>
      </form>

      <div className="space-y-4">
        {comments.map((comment) => (
          <Comment key={comment.id} comment={comment} />
        ))}
      </div>
    </div>
  );
};

export default CourseDiscussion;
