import { Fragment, useState, useEffect } from 'react';
import { Menu, Transition } from '@headlessui/react';
import { BellIcon } from '@heroicons/react/24/solid';
import { useSelector, useDispatch } from 'react-redux';
import { markAsRead } from '../store/slices/notificationsSlice';
import api from '../services/api';

const NotificationCenter = () => {
  const dispatch = useDispatch();
  const notifications = useSelector(state => state.notifications.items);
  const unreadCount = notifications.filter(n => !n.read).length;

  const handleMarkAsRead = async (notificationId) => {
    try {
      await api.post(`/notifications/${notificationId}/read`);
      dispatch(markAsRead(notificationId));
    } catch (error) {
      console.error('Erro ao marcar notificação como lida:', error);
    }
  };

  return (
    <Menu as="div" className="relative">
      <Menu.Button className="relative p-1 rounded-full text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
        <BellIcon className="h-6 w-6" />
        {unreadCount > 0 && (
          <span className="absolute top-0 right-0 -mt-1 -mr-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-xs text-white">
            {unreadCount}
          </span>
        )}
      </Menu.Button>

      <Transition
        as={Fragment}
        enter="transition ease-out duration-100"
        enterFrom="transform opacity-0 scale-95"
        enterTo="transform opacity-100 scale-100"
        leave="transition ease-in duration-75"
        leaveFrom="transform opacity-100 scale-100"
        leaveTo="transform opacity-0 scale-95"
      >
        <Menu.Items className="absolute right-0 mt-2 w-80 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none">
          <div className="py-1">
            {notifications.length === 0 ? (
              <div className="px-4 py-3 text-sm text-gray-500">
                Nenhuma notificação
              </div>
            ) : (
              notifications.map(notification => (
                <Menu.Item key={notification.id}>
                  {({ active }) => (
                    <div
                      className={`
                        ${active ? 'bg-gray-50' : ''}
                        ${!notification.read ? 'bg-blue-50' : ''}
                        px-4 py-3 cursor-pointer
                      `}
                      onClick={() => handleMarkAsRead(notification.id)}
                    >
                      <p className="text-sm font-medium text-gray-900">
                        {notification.title}
                      </p>
                      <p className="text-sm text-gray-500 mt-1">
                        {notification.message}
                      </p>
                      <p className="text-xs text-gray-400 mt-1">
                        {new Date(notification.createdAt).toLocaleString()}
                      </p>
                    </div>
                  )}
                </Menu.Item>
              ))
            )}
          </div>
        </Menu.Items>
      </Transition>
    </Menu>
  );
};

export default NotificationCenter;
