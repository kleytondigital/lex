const Feature = ({ icon: Icon, title, description }) => {
  return (
    <div className="flex items-start space-x-4">
      <div className="flex-shrink-0">
        <Icon className="h-5 w-5 text-blue-300" aria-hidden="true" />
      </div>
      <div>
        <h3 className="text-lg font-semibold text-white">{title}</h3>
        <p className="text-blue-200">{description}</p>
      </div>
    </div>
  );
};

export default Feature; 