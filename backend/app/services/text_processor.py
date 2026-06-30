"""
Text processing service.
"""

from typing import List, Optional
from ..utils.file_parser import FileParser, split_text_into_chunks


class TextProcessor:
    """Text processor utility."""

    @staticmethod
    def extract_from_files(file_paths: List[str]) -> str:
        """Extract text from multiple files."""
        return FileParser.extract_from_multiple(file_paths)

    @staticmethod
    def split_text(
        text: str,
        chunk_size: int = 500,
        overlap: int = 50
    ) -> List[str]:
        """
        Split text into overlapping chunks.

        Args:
            text: source text
            chunk_size: maximum characters per chunk
            overlap: overlap between consecutive chunks

        Returns:
            list of text chunks
        """
        return split_text_into_chunks(text, chunk_size, overlap)

    @staticmethod
    def preprocess_text(text: str) -> str:
        """
        Normalize text:
        - remove excessive whitespace
        - normalize line endings
        """
        import re

        # normalize line endings
        text = text.replace('\r\n', '\n').replace('\r', '\n')

        # collapse runs of blank lines (keep at most two newlines)
        text = re.sub(r'\n{3,}', '\n\n', text)

        # strip leading/trailing whitespace on each line
        lines = [line.strip() for line in text.split('\n')]
        text = '\n'.join(lines)

        return text.strip()

    @staticmethod
    def get_text_stats(text: str) -> dict:
        """Return basic statistics for a text string."""
        return {
            "total_chars": len(text),
            "total_lines": text.count('\n') + 1,
            "total_words": len(text.split()),
        }
