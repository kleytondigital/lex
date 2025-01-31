import {
    Bars3Icon,
    XMarkIcon,
    BellIcon,
    MagnifyingGlassIcon
} from '@heroicons/react/24/outline'; 

// No JSX onde os ícones são usados
<button className="mobile-menu-button">
    {isOpen ? (
        <XMarkIcon className="h-6 w-6" />
    ) : (
        <Bars3Icon className="h-6 w-6" />
    )}
</button>

<div className="search-bar">
    <MagnifyingGlassIcon className="h-5 w-5" />
</div>

<div className="notifications">
    <BellIcon className="h-6 w-6" />
</div> 