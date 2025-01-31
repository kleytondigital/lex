import { useState } from 'react';
import { templates } from '../../data/templates';

const TemplateSelector = ({ objective, currentTemplate, onSelect }) => {
    const [selectedTemplate, setSelectedTemplate] = useState(currentTemplate);
    
    // Converte o objeto de templates para um array
    const availableTemplates = objective && templates[objective] ? 
        Object.values(templates[objective]) : [];

    const handleSelect = (template) => {
        setSelectedTemplate(template.id);
        onSelect(template);
    };

    return (
        <div className="space-y-4">
            <h3 className="text-lg font-medium text-gray-200">
                Escolha um Template
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {availableTemplates.map((template) => (
                    <div
                        key={template.id}
                        className={`relative rounded-lg border-2 overflow-hidden cursor-pointer transition-all
                            ${selectedTemplate === template.id 
                                ? 'border-orange-500 shadow-lg shadow-orange-500/20' 
                                : 'border-gray-700 hover:border-gray-600'}`}
                        onClick={() => handleSelect(template)}
                    >
                        <div className="aspect-video bg-gray-800">
                            <img
                                src={template.thumbnail}
                                alt={template.name}
                                className="w-full h-full object-cover"
                                onError={(e) => {
                                    e.target.src = 'https://via.placeholder.com/400x225?text=Template+Preview';
                                }}
                            />
                        </div>
                        <div className="p-4 bg-gray-900/50">
                            <h4 className="text-sm font-medium text-gray-200">
                                {template.name}
                            </h4>
                            <p className="mt-1 text-xs text-gray-400">
                                {template.description}
                            </p>
                        </div>
                        {selectedTemplate === template.id && (
                            <div className="absolute top-2 right-2 bg-orange-500 text-white text-xs px-2 py-1 rounded">
                                Selecionado
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

export default TemplateSelector; 