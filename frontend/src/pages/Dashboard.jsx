import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
    AcademicCapIcon,
    ClockIcon,
    UserGroupIcon,
    TrophyIcon
} from '@heroicons/react/24/outline';
import api from '../services/api';
import CourseCard from '../components/CourseCard';

const Dashboard = () => {
    const [stats, setStats] = useState({
        totalCourses: 0,
        completedCourses: 0,
        studyHours: 0,
        certificates: 0
    });
    const [enrolledCourses, setEnrolledCourses] = useState([]);
    const [recommendedCourses, setRecommendedCourses] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchData();
    }, []);

    const fetchData = async () => {
        try {
            const [statsRes, enrolledRes, recommendedRes] = await Promise.all([
                api.get('/user/stats'),
                api.get('/courses/enrolled'),
                api.get('/courses/recommended')
            ]);

            setStats(statsRes.data);
            setEnrolledCourses(enrolledRes.data || []);
            setRecommendedCourses(recommendedRes.data || []);
        } catch (error) {
            console.error('Erro ao carregar dados:', error);
        } finally {
            setLoading(false);
        }
    };

    const statCards = [
        { name: 'Total de Cursos', value: stats.totalCourses, icon: AcademicCapIcon },
        { name: 'Cursos Concluídos', value: stats.completedCourses, icon: TrophyIcon },
        { name: 'Horas Estudadas', value: `${stats.studyHours}h`, icon: ClockIcon },
        { name: 'Certificados', value: stats.certificates, icon: UserGroupIcon },
    ];

    if (loading) {
        return (
                <div className="flex justify-center items-center h-screen">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-orange-500"></div>
                </div>
        );
    }

    return (
            <div className="space-y-8">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
                {statCards.map((stat) => (
                    <div
                        key={stat.name}
                        className="relative overflow-hidden rounded-lg bg-gray-800 px-4 py-5 shadow sm:px-6 sm:py-6"
                    >
                        <dt>
                            <div className="absolute rounded-md bg-orange-500 p-3">
                                <stat.icon className="h-6 w-6 text-white" aria-hidden="true" />
                            </div>
                            <p className="ml-16 truncate text-sm font-medium text-gray-400">{stat.name}</p>
                        </dt>
                        <dd className="ml-16 flex items-baseline">
                            <p className="text-2xl font-semibold text-white">{stat.value}</p>
                        </dd>
                    </div>
                ))}
            </div>

            {/* Continue Learning Section */}
            <section className="bg-gray-800/50 rounded-lg p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-bold text-white">Continue Aprendendo</h2>
                    <Link
                        to="/courses"
                        className="text-orange-500 hover:text-orange-400 text-sm font-semibold"
                    >
                        Ver todos os cursos
                    </Link>
                </div>
                    {enrolledCourses.length > 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {enrolledCourses.map(course => (
                                <CourseCard key={course.id} course={course} />
                            ))}
                        </div>
                    ) : (
                    <div className="text-center py-12 bg-gray-900/50 rounded-lg">
                        <AcademicCapIcon className="mx-auto h-12 w-12 text-gray-400" />
                        <h3 className="mt-2 text-sm font-semibold text-gray-400">Nenhum curso em andamento</h3>
                        <p className="mt-1 text-sm text-gray-500">Comece agora mesmo sua jornada de aprendizado.</p>
                        <div className="mt-6">
                            <Link
                                to="/courses"
                                className="inline-flex items-center rounded-md bg-orange-500 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-orange-600"
                            >
                                Explorar cursos
                            </Link>
                        </div>
                    </div>
                    )}
                </section>

            {/* Recommended Courses */}
            <section className="bg-gray-800/50 rounded-lg p-6">
                <h2 className="text-2xl font-bold text-white mb-6">Recomendados para Você</h2>
                    {recommendedCourses.length > 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {recommendedCourses.map(course => (
                                <CourseCard key={course.id} course={course} />
                            ))}
                        </div>
                    ) : (
                    <p className="text-center text-gray-400 py-4">
                        Nenhum curso recomendado no momento.
                    </p>
                    )}
                </section>
            </div>
    );
};

export default Dashboard; 