import { Link } from 'react-router-dom';
import { PlayCircleIcon, ClockIcon } from '@heroicons/react/24/outline';

const CourseCard = ({ course }) => {
    return (
        <div className="flex flex-col bg-gray-900 rounded-lg overflow-hidden hover:ring-1 hover:ring-orange-500/50 transition-all duration-300">
            <div className="relative">
                <img
                    src={course.thumbnail}
                    alt={course.name}
                    className="h-48 w-full object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-gray-900/75 to-transparent" />
                {course.progress > 0 && (
                    <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-700">
                        <div
                            className="h-full bg-orange-500"
                            style={{ width: `${course.progress}%` }}
                        />
                    </div>
                )}
            </div>
            <div className="flex-1 p-4">
                <h3 className="text-lg font-semibold text-white mb-2">{course.name}</h3>
                <p className="text-sm text-gray-400 mb-4 line-clamp-2">{course.description}</p>
                <div className="flex items-center justify-between mt-auto">
                    <div className="flex items-center text-sm text-gray-400">
                        <ClockIcon className="h-4 w-4 mr-1" />
                        {course.duration}h
                    </div>
                    <Link
                        to={`/course/${course.id}`}
                        className="inline-flex items-center text-orange-500 hover:text-orange-400"
                    >
                        <PlayCircleIcon className="h-5 w-5 mr-1" />
                        {course.progress > 0 ? 'Continuar' : 'Começar'}
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default CourseCard;
