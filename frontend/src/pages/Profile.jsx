import { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  UserCircleIcon, 
  AcademicCapIcon, 
  ClockIcon, 
  CheckBadgeIcon } from '@heroicons/react/24/outline';
import Layout from '../components/Layout';
import Certificate from '../components/Certificate';
import api from '../services/api';

const Profile = () => {
  const [userData, setUserData] = useState({
    stats: null,
    completedCourses: [],
    profile: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchUserData();
  }, []);

  const fetchUserData = async () => {
    try {
      const [statsRes, coursesRes, profileRes] = await Promise.all([
        api.get('/user/stats'),
        api.get('/user/completed-courses'),
        api.get('/user/profile')
      ]);

      setUserData({
        stats: statsRes.data || {
          totalCourses: 0,
          completedCourses: 0,
          hoursWatched: 0,
          certificatesEarned: 0
        },
        completedCourses: coursesRes.data || [],
        profile: profileRes.data
      });
    } catch (error) {
      console.error('Erro ao carregar dados do usuário:', error);
      setError('Erro ao carregar dados do usuário');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return (
    <Layout>
      <div className="flex justify-center items-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
      </div>
    </Layout>
  );

  if (error) return (
    <Layout>
      <div className="flex justify-center items-center h-screen">
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative">
          <strong className="font-bold">Erro! </strong>
          <span className="block sm:inline">{error}</span>
        </div>
      </div>
    </Layout>
  );

  if (!userData.profile) return <div>Perfil não encontrado</div>;

  return (
    <Layout>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Cabeçalho do Perfil */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              {userData.profile.avatar ? (
                <img
                  src={userData.profile.avatar}
                  alt={userData.profile.name}
                  className="h-20 w-20 rounded-full"
                />
              ) : (
                <UserCircleIcon className="h-20 w-20 text-gray-400" />
              )}
            </div>
            <div className="ml-6">
              <h1 className="text-2xl font-bold text-gray-900">{userData.profile.name}</h1>
              <p className="text-sm text-gray-500">{userData.profile.email}</p>
              <p className="text-sm text-gray-500">
                Membro desde {new Date(userData.profile.createdAt).toLocaleDateString()}
              </p>
            </div>
          </div>
        </div>

        {/* Estatísticas */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center">
              <AcademicCapIcon className="h-8 w-8 text-blue-500" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Cursos Concluídos</p>
                <p className="text-2xl font-semibold text-gray-900">{userData.stats.completedCourses}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center">
              <ClockIcon className="h-8 w-8 text-green-500" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Horas de Estudo</p>
                <p className="text-2xl font-semibold text-gray-900">{userData.stats.studyHours}h</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex items-center">
              <CheckBadgeIcon  className="h-8 w-8 text-yellow-500" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">Certificados</p>
                <p className="text-2xl font-semibold text-gray-900">{userData.stats.certificates}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Certificados */}
        <h2 className="text-xl font-bold text-gray-900 mb-4">Meus Certificados</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {userData.completedCourses.map(course => (
            <Certificate
              key={course.id}
              courseId={course.id}
              courseName={course.name}
              completionDate={course.completedAt}
            />
          ))}
        </div>

        {/* Cursos Concluídos */}
        <section className="mt-8">
          <h3 className="text-xl font-semibold text-gray-200 mb-4">Cursos Concluídos</h3>
          {userData.completedCourses.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {userData.completedCourses.map(course => (
                <Certificate
                  key={course.id}
                  courseId={course.id}
                  courseName={course.name}
                  completionDate={course.completedAt}
                />
              ))}
            </div>
          ) : (
            <p className="text-gray-400">Você ainda não concluiu nenhum treinamento.</p>
          )}
        </section>
      </div>
    </Layout>
  );
};

export default Profile; 