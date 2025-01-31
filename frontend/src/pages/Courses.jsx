import { useState, useEffect } from 'react';
import { MagnifyingGlassIcon } from '@heroicons/react/24/solid';
import Layout from '../components/Layout';
import CourseCard from '../components/CourseCard';
import api from '../services/api';

const Courses = () => {
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');

  useEffect(() => {
    fetchCourses();
  }, []);

  const fetchCourses = async () => {
    try {
      const response = await api.get('/courses');
      setCourses(response.data);
    } catch (error) {
      console.error('Erro ao carregar cursos:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredCourses = courses.filter(course => {
    const matchesSearch = course.name.toLowerCase().includes(search.toLowerCase()) ||
                         course.description.toLowerCase().includes(search.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || course.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <Layout>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Cursos Disponíveis</h1>
        <p className="mt-1 text-sm text-gray-500">
          Explore nossa biblioteca de cursos e comece sua jornada de aprendizado
        </p>
      </div>

      <div className="mb-6 flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Buscar cursos..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        
        <select
          value={selectedCategory}
          onChange={(e) => setSelectedCategory(e.target.value)}
          className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        >
          <option value="all">Todas as categorias</option>
          <option value="programming">Programação</option>
          <option value="design">Design</option>
          <option value="business">Negócios</option>
          <option value="marketing">Marketing</option>
        </select>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredCourses.map((course) => (
            <CourseCard
              key={course.id}
              course={course}
              onClick={() => navigate(`/courses/${course.id}`)}
            />
          ))}
        </div>
      )}
    </Layout>
  );
};

export default Courses;
