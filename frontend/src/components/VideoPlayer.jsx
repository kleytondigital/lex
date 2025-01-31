import { useRef, useEffect } from 'react';
import {
    PlayIcon,
    PauseIcon,
    SpeakerWaveIcon,
    SpeakerXMarkIcon,
    ArrowsPointingOutIcon
} from '@heroicons/react/24/solid';

const VideoPlayer = ({ lesson }) => {
  const videoRef = useRef(null);

  useEffect(() => {
    // Salvar o progresso do vídeo periodicamente
    const interval = setInterval(() => {
      if (videoRef.current) {
        const progress = {
          lessonId: lesson.id,
          currentTime: videoRef.current.currentTime,
          duration: videoRef.current.duration,
          completed: videoRef.current.currentTime === videoRef.current.duration
        };
        // Enviar progresso para a API
        saveProgress(progress);
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [lesson]);

  const saveProgress = async (progress) => {
    try {
      await api.post(`/lessons/${lesson.id}/progress`, progress);
    } catch (error) {
      console.error('Erro ao salvar progresso:', error);
    }
  };

  return (
    <div className="aspect-w-16 aspect-h-9 bg-black rounded-lg overflow-hidden">
      <video
        ref={videoRef}
        src={lesson.videoUrl}
        controls
        className="w-full h-full object-contain"
        poster={lesson.thumbnailUrl}
      >
        <track
          kind="captions"
          src={lesson.captionsUrl}
          srcLang="pt-BR"
          label="Português"
        />
      </video>
      <button onClick={togglePlay}>
        {isPlaying ? (
          <PauseIcon className="h-6 w-6" />
        ) : (
          <PlayIcon className="h-6 w-6" />
        )}
      </button>
      <button onClick={toggleMute}>
        {isMuted ? (
          <SpeakerXMarkIcon className="h-6 w-6" />
        ) : (
          <SpeakerWaveIcon className="h-6 w-6" />
        )}
      </button>
      <button onClick={toggleFullscreen}>
        <ArrowsPointingOutIcon className="h-6 w-6" />
      </button>
    </div>
  );
};

export default VideoPlayer; 