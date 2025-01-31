export const templates = {
    client: {
        'modern-client': {
            id: 'modern-client',
            name: 'Moderno - Captura de Clientes',
            description: 'Template moderno focado em captura de clientes com destaque para benefícios e economia',
            thumbnail: '/templates/modern-client.png',
            defaultContent: {
                headline: 'DESCUBRA COMO RECEBER ATÉ 40% DE DESCONTO NA SUA CONTA DE LUZ TODOS OS MESES GRATUITAMENTE',
                subheadline: 'Conheça agora a oportunidade e como você pode economizar na conta de luz da sua residência, comércio e empresa sem investimentos',
                features: [
                    'Economia de até 40% todos os meses na sua conta de luz',
                    'Benefícios gratuitos',
                    'Sem custos adicionais',
                    'Sem burocracia e riscos',
                    'Sem fidelidade',
                    'Sem necessidade de comprar equipamentos',
                    '100% digital'
                ],
                howItWorks: {
                    title: 'COMO FUNCIONA',
                    steps: [
                        'Nossa tecnologia produz energia limpa e renovável',
                        'A energia é injetada na rede da distribuidora',
                        'A distribuidora envia a energia para sua residência ou empresa',
                        'Você economiza de forma gratuita sem investimentos'
                    ]
                },
                faq: [{
                        question: 'Por que o serviço é mais barato?',
                        answer: 'Utilizamos um modelo avançado de análise e otimização com inteligência artificial, que identifica o melhor padrão para cada cliente. Isso nos permite repassar economias diretas aos consumidores.'
                    },
                    {
                        question: 'Como funciona o pagamento?',
                        answer: 'Você receberá apenas um único boleto unificado, simplificando o processo de pagamento.'
                    },
                    {
                        question: 'Existe algum custo para começar?',
                        answer: 'Não, você não paga nenhum centavo para ter acesso aos benefícios. Não precisa instalar equipamentos, não tem taxa de adesão, não tem mensalidade e não tem fidelidade.'
                    }
                ],
                cta: {
                    primary: 'QUERO ECONOMIZAR AGORA',
                    secondary: 'ATENDIMENTO NO WHATSAPP'
                },
                consultant: {
                    name: 'Seu Nome',
                    role: 'CONSULTOR',
                    message: 'Estou muito feliz com seu interesse e será um grande prazer tê-lo(a) conosco. Estou à disposição para tirar todas as suas dúvidas e fornecer o melhor suporte. Pode contar comigo!'
                }
            }
        },
        'minimal-client': {
            id: 'minimal-client',
            name: 'Minimalista - Captura de Clientes',
            description: 'Template minimalista focado em conversão direta de clientes',
            thumbnail: '/templates/minimal-client.png',
            defaultContent: {
                headline: 'REDUZA SUA CONTA DE LUZ EM ATÉ 40% SEM NENHUM INVESTIMENTO',
                subheadline: 'Descubra como você pode economizar todos os meses de forma 100% gratuita e sem burocracia',
                features: [
                    'Economia garantida todo mês',
                    'Zero investimento inicial',
                    'Processo 100% digital',
                    'Sem fidelidade',
                    'Atendimento personalizado'
                ],
                cta: {
                    primary: 'QUERO ECONOMIZAR',
                    secondary: 'FALAR COM CONSULTOR'
                },
                consultant: {
                    name: 'Seu Nome',
                    role: 'ESPECIALISTA EM ECONOMIA DE ENERGIA',
                    message: 'Olá! Estou aqui para ajudar você a reduzir seus custos com energia. Vamos conversar?'
                }
            }
        }
    },
    consultant: {
        'modern-consultant': {
            id: 'modern-consultant',
            name: 'Moderno - Captura de Consultores',
            description: 'Template moderno para atração de consultores com foco em benefícios e oportunidades',
            thumbnail: '/templates/modern-consultant.png',
            defaultContent: {
                headline: 'TORNE-SE UM CONSULTOR DE ENERGIA E FATURE ATÉ R$10.000 POR MÊS',
                subheadline: 'Descubra como você pode iniciar sua carreira no mercado de energia renovável com zero investimento',
                features: [
                    'Ganhos acima da média do mercado',
                    'Trabalhe de onde quiser',
                    'Suporte completo para iniciar',
                    'Treinamento especializado',
                    'Sistema exclusivo de gestão',
                    'Produtos inovadores',
                    'Mercado em expansão'
                ],
                howItWorks: {
                    title: 'COMO FUNCIONA',
                    steps: [
                        'Faça seu cadastro gratuito',
                        'Receba treinamento completo',
                        'Comece a prospectar clientes',
                        'Receba comissões recorrentes'
                    ]
                },
                cta: {
                    primary: 'QUERO SER CONSULTOR',
                    secondary: 'SAIBA MAIS'
                },
                consultant: {
                    name: 'Seu Nome',
                    role: 'GESTOR DE EXPANSÃO',
                    message: 'Estou aqui para te ajudar a iniciar sua carreira como consultor. Vamos conversar sobre essa oportunidade?'
                }
            }
        },
        'minimal-consultant': {
            id: 'minimal-consultant',
            name: 'Minimalista - Captura de Consultores',
            description: 'Template minimalista para recrutamento de consultores',
            thumbnail: '/templates/minimal-consultant.png',
            defaultContent: {
                headline: 'SEJA UM CONSULTOR DE ENERGIA RENOVÁVEL',
                subheadline: 'Inicie uma carreira promissora no mercado que mais cresce no Brasil',
                features: [
                    'Altos ganhos em comissões',
                    'Flexibilidade de horário',
                    'Treinamento incluído',
                    'Suporte completo',
                    'Sem investimento inicial'
                ],
                cta: {
                    primary: 'COMEÇAR AGORA',
                    secondary: 'MAIS INFORMAÇÕES'
                },
                consultant: {
                    name: 'Seu Nome',
                    role: 'COORDENADOR DE EXPANSÃO',
                    message: 'Quer saber mais sobre como se tornar um consultor de sucesso? Vamos conversar!'
                }
            }
        }
    }
};