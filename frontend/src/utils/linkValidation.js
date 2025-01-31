export const validateWhatsAppLink = (link) => {
    if (!link) return { isValid: true, message: '' }; // Link vazio é permitido

    const whatsappPattern = /^https:\/\/wa\.me\/\d+/;
    if (!whatsappPattern.test(link)) {
        return {
            isValid: false,
            message: 'O link do WhatsApp deve começar com https://wa.me/ seguido do número'
        };
    }
    return { isValid: true, message: '' };
};

export const validateEmailLink = (link) => {
    if (!link) return { isValid: true, message: '' }; // Link vazio é permitido

    try {
        new URL(link);
        return { isValid: true, message: '' };
    } catch {
        return {
            isValid: false,
            message: 'Por favor, insira uma URL válida'
        };
    }
};

export const formatWhatsAppLink = (phoneNumber) => {
    // Remove todos os caracteres não numéricos
    const numbers = phoneNumber.replace(/\D/g, '');

    // Verifica se começa com https://wa.me/
    if (numbers.startsWith('https://wa.me/')) {
        return numbers;
    }

    // Adiciona o prefixo se necessário
    return `https://wa.me/${numbers}`;
};