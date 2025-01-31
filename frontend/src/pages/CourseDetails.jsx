import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { PlayCircleIcon, BookOpenIcon, ClockIcon, StarIcon } from '@heroicons/react/24/solid';
import Layout from '../components/Layout';
import VideoPlayer from '../components/VideoPlayer';
import api from '../services/api';
import CourseProgress from '../components/CourseProgress';
import CourseResources from '../components/CourseResources';
import CourseDiscussion from '../components/CourseDiscussion';
import CourseReview from '../components/CourseReview';

const CourseDetails = () => {
  const { id } = useParams();
  const [course, setCourse] = useState(null);
  const [activeLesson, setActiveLesson] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCourseDetails();
  }, [id]);

  const fetchCourseDetails = async () => {
    try {
      const response = await api.get(`/courses/${id}`);
      setCourse(response.data);
      setActiveLesson(response.data.lessons[0]);
    } catch (error) {
      console.error('Erro ao carregar detalhes do curso:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex justify-center items-center h-96">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Área principal - Vídeo e detalhes */}
        <div className="lg:col-span-2">
          <VideoPlayer lesson={activeLesson} />
          
          <div className="mt-6 bg-white rounded-lg shadow-sm p-6">
            <h1 className="text-2xl font-bold text-gray-900">{course.name}</h1>
            <p className="mt-2 text-gray-600">{course.description}</p>
            
            <div className="mt-4 flex items-center space-x-4 text-sm text-gray-500">
              <div className="flex items-center">
                <ClockIcon className="h-5 w-5 mr-1" />
                {course.duration}
              </div>
              <div className="flex items-center">
                <BookOpenIcon className="h-5 w-5 mr-1" />
                {course.lessons.length} aulas
              </div>
              <div className="flex items-center">
                <StarIcon className="h-5 w-5 mr-1" />
                {course.rating} ({course.reviewsCount} avaliações)
              </div>
            </div>
          </div>
          
          <div className="mt-8">
            <CourseDiscussion 
              courseId={course.id} 
              lessonId={activeLesson.id} 
            />
          </div>
          
          <div className="mt-8">
            <CourseReview 
              courseId={course.id}
              onReviewSubmitted={fetchCourseDetails}
            />
          </div>
        </div>

        {/* Sidebar - Lista de aulas */}
        <div className="space-y-6">
          <CourseProgress courseId={course.id} />
          
          <div className="bg-white rounded-lg shadow-sm p-4">
            <h2 className="font-semibold text-lg mb-4">Conteúdo do Curso</h2>
            <div className="space-y-2">
              {course.lessons.map((lesson) => (
                <button
                  key={lesson.id}
                  onClick={() => setActiveLesson(lesson)}
                  className={`w-full flex items-center p-3 rounded-lg text-left transition-colors ${
                    activeLesson?.id === lesson.id
                      ? 'bg-blue-50 text-blue-700'
                      : 'hover:bg-gray-50'
                  }`}
                >
                  <PlayCircleIcon className="h-5 w-5 mr-3 flex-shrink-0" />
                  <div className="flex-1">
                    <h3 className="font-medium">{lesson.title}</h3>
                    <p className="text-sm text-gray-500">{lesson.duration}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>
          
          <CourseResources resources={course.resources} />
        </div>
      </div>

      {/* Seção de Avaliações */}
      <div className="mt-8">
        <h2 className="text-xl font-bold mb-4">Avaliações dos Alunos</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {course.reviews.map((review) => (
            <div key={review.id} className="bg-white rounded-lg shadow-sm p-4">
              <div className="flex items-center mb-2">
                <img
                  src={review.userAvatar}
                  alt={review.userName}
                  className="h-10 w-10 rounded-full"
                />
                <div className="ml-3">
                  <h3 className="font-medium">{review.userName}</h3>
                  <div className="flex items-center text-yellow-400">
                    {[...Array(5)].map((_, i) => (
                      <StarIcon
                        key={i}
                        className={`h-4 w-4 ${
                          i < review.rating ? 'fill-current' : 'stroke-current'
                        }`}
                      />
                    ))}
                  </div>
                </div>
              </div>
              <p className="text-gray-600">{review.comment}</p>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
};

export default CourseDetails;
