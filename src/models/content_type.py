from enum import Enum

class ContentType(Enum):
    LYRICS = "lyrics"
    SCORE = "score"
    AUDIO_MP3 = "audio/mp3"
    AUDIO_WAV = "audio/wav"
    VIDEO_MP4 = "video/mp4"
    VIDEO_AVI = "video/avi"
    DOCUMENT = "document"
    OTHER = "other"

    @classmethod
    def from_extension(cls, extension: str) -> 'ContentType':
        """Get content type from file extension"""
        extension = extension.lower().lstrip('.')
        mapping = {
            'mp3': cls.AUDIO_MP3,
            'wav': cls.AUDIO_WAV,
            'mp4': cls.VIDEO_MP4,
            'avi': cls.VIDEO_AVI,
            'txt': cls.LYRICS,
            'pdf': cls.SCORE,
            'doc': cls.DOCUMENT,
            'docx': cls.DOCUMENT
        }
        return mapping.get(extension, cls.OTHER) 