import { useState, useEffect } from 'react';
import api from '../../services/api';
import { 
    AcademicCapIcon,
    ArrowRightIcon,
    EyeIcon 
} from '@heroicons/react/24/outline';

const CoursesList = () => {
    const [courses, setCourses] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchCourses = async () => {
            try {
                const response = await api.get('/admin/courses?limit=5');
                setCourses(response.data);
            } catch (error) {
                console.error('Erro ao buscar cursos:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchCourses();
    }, []);

    if (loading) return <div>Carregando...</div>;

    return (
        <div className="bg-[#1a1a1a] rounded-lg shadow-lg p-6">
            <div className="px-4 py-5 sm:px-6">
                <h3 className="text-lg leading-6 font-medium text-gray-300">
                    Cursos Recentes
                </h3>
            </div>
            <div className="border-t border-gray-700">
                <ul className="divide-y divide-gray-700">
                    {courses.map((course) => (
                        <li key={course.id} className="px-4 py-4 sm:px-6">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center">
                                    <div className="flex-shrink-0">
                                        <img
                                            className="h-12 w-12 rounded-lg object-cover"
                                            src={course.thumbnail || '/default-course.png'}
                                            alt=""
                                        />
                                    </div>
                                    <div className="ml-3">
                                        <p className="text-sm font-medium text-gray-500">{course.name}</p>
                                        <p className="text-sm text-gray-500">{course.instructor}</p>
                                    </div>
                                </div>
                                <div className="ml-3">
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                        course.status === 'published' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                                    }`}>
                                        {course.status}
                                    </span>
                                </div>
                                <div className="course-icons">
                                    <AcademicCapIcon className="h-6 w-6" />
                                    <ArrowRightIcon className="h-5 w-5" />
                                    <EyeIcon className="h-5 w-5" />
                                </div>
                            </div>
                        </li>
                    ))}
                </ul>
            </div>
        </div>
    );
};

export default CoursesList; 