import { DocumentTextIcon, ArrowDownTrayIcon, ArrowTopRightOnSquareIcon } from '@heroicons/react/24/solid';

const CourseResources = ({ resources }) => {
  return (
    <div className="bg-white rounded-lg shadow-sm p-6">
      <h3 className="text-lg font-semibold mb-4">Material Complementar</h3>
      <div className="space-y-4">
        {resources.map((resource) => (
          <div
            key={resource.id}
            className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <div className="flex items-center">
              <DocumentTextIcon className="h-5 w-5 text-gray-400 mr-3" />
              <div>
                <h4 className="text-sm font-medium text-gray-900">{resource.title}</h4>
                <p className="text-xs text-gray-500">{resource.type} • {resource.size}</p>
              </div>
            </div>
            
            {resource.type === 'download' ? (
              <a
                href={resource.url}
                download
                className="p-2 text-gray-400 hover:text-gray-600"
              >
                <ArrowDownTrayIcon className="h-5 w-5" />
              </a>
            ) : (
              <a
                href={resource.url}
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 text-gray-400 hover:text-gray-600"
              >
                <ArrowTopRightOnSquareIcon className="h-5 w-5" />
              </a>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default CourseResources;
