# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

# LEX Platform - Landing Page Module Documentation

## Overview
The LEX Platform includes a landing page module that allows users to create and manage landing pages for client acquisition and consultant recruitment.

## Database Schema

### Main Tables

**landing_pages**

### Configuration Tables

- landing_page_seo
- landing_page_integrations  
- landing_page_pixels
- landing_page_media
- integration_settings
- email_templates

## Backend Architecture

### Controllers
- LandingPageController - Main landing page CRUD operations
- LeadController - Lead management 
- WhatsAppController - WhatsApp integration
- EmailController - Email notifications
- SpreadsheetController - Google Sheets integration

### Services
- emailService - Email notifications when receiving leads
- spreadsheetService - Save leads to Google Sheets
- whatsappService - WhatsApp notifications
- paymentService - Process payments via Mercado Pago

### Routes
- /landpages - Landing page management
- /leads - Lead management
- /whatsapp - WhatsApp integration
- /spreadsheet - Google Sheets integration
- /email - Email templates and notifications

## Frontend Architecture

### Pages
- LandingPages.jsx - List landing pages
- NewLandingPage.jsx - Create new landing page
- LandingPageConfig.jsx - Configure landing page
- Leads.jsx - Lead management
- ClientTemplate.jsx - Client landing page template
- ConsultantTemplate.jsx - Consultant landing page template

### Components
- ConfigForm.jsx - Landing page configuration form
- ImageUpload.jsx - Media upload component
- DashboardSidebar.jsx - Navigation sidebar
- DashboardLayout.jsx - Layout wrapper

## Features

### Landing Page Creation
- Digital name configuration
- Template selection (client/consultant)
- Media upload
- SEO settings
- Integration settings
- Pixel tracking

### Lead Management
- Lead capture forms
- Lead status tracking
- Lead notifications
- Export to spreadsheet
- WhatsApp notifications
- Email notifications

### Integrations
- Google Sheets
- WhatsApp
- Email
- Webhooks
- Facebook Pixel
- Google Analytics
- TikTok Pixel

## Development Status

Completed:
- Basic database schema
- Landing page CRUD
- Lead capture
- Basic templates

In Progress:
- Integration implementations
- Media management
- Analytics
- Template customization

To Do:
- A/B testing
- Advanced analytics
- More templates
- Campaign tracking
- Custom domains

## Environment Variables Required

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=lex_db
JWT_SECRET=sua_chave_secreta
EMAIL_HOST=smtp.exemplo.com
EMAIL_PORT=587
EMAIL_USER=seu_email@exemplo.com
EMAIL_PASS=sua_senha_email
MP_ACCESS_TOKEN=
MP_PUBLIC_KEY=

## Next Steps

1. Complete integration implementations
2. Add more landing page templates
3. Implement A/B testing
4. Add campaign tracking
5. Improve analytics dashboard
6. Add custom domain support
7. Implement template customization
8. Add more export options
9. Improve lead scoring
10. Add automation features

## Notes for Developers

- Follow existing code style and patterns
- Use provided utility functions
- Maintain separation of concerns
- Document new features
- Write tests for critical functionality
- Consider scalability in implementations
- Follow security best practices
- Keep dependencies updated
