"""Secure PDF download, page-aware extraction, search, and bounded caching."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
import pymupdf

from config import Settings


class PDFProcessingError(RuntimeError):
    """A safe-to-display PDF processing failure."""


@dataclass(frozen=True, slots=True)
class PDFPage:
    page_number: int
    text: str


@dataclass(frozen=True, slots=True)
class PDFDocument:
    report_id: str
    content: bytes
    pages: tuple[PDFPage, ...]
    ocr_required_pages: tuple[int, ...]

    @property
    def estimated_bytes(self) -> int:
        return len(self.content) + sum(len(page.text.encode("utf-8")) for page in self.pages)


class PDFProcessor:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        self.settings = settings
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout_seconds), follow_redirects=False
        )
        self._owns_client = client is None
        self._cache: OrderedDict[str, tuple[float, PDFDocument]] = OrderedDict()
        self._cache_bytes = 0
        self._cache_lock = asyncio.Lock()
        self._report_locks: dict[str, asyncio.Lock] = {}

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise PDFProcessingError("InsightMonk returned an unsafe PDF URL.")

        try:
            addresses = await asyncio.to_thread(
                socket.getaddrinfo,
                parsed.hostname,
                parsed.port or 443,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as error:
            raise PDFProcessingError("The PDF host could not be resolved.") from error
        if not addresses:
            raise PDFProcessingError("The PDF host could not be resolved.")
        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])
            if not ip.is_global:
                raise PDFProcessingError("InsightMonk returned an unsafe PDF URL.")

    async def _download(self, url: str) -> bytes:
        current_url = url
        for _ in range(4):
            await self._validate_url(current_url)
            try:
                async with self._client.stream(
                    "GET", current_url, headers={"Accept": "application/pdf"}
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            raise PDFProcessingError("The PDF download redirect is invalid.")
                        current_url = urljoin(current_url, location)
                        continue
                    if response.status_code >= 400:
                        raise PDFProcessingError("The report PDF could not be downloaded.")

                    content_length = response.headers.get("content-length")
                    if content_length:
                        try:
                            if int(content_length) > self.settings.pdf_max_download_bytes:
                                raise PDFProcessingError("The report PDF exceeds the download limit.")
                        except ValueError:
                            pass

                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > self.settings.pdf_max_download_bytes:
                            raise PDFProcessingError("The report PDF exceeds the download limit.")
                        chunks.append(chunk)
                    content = b"".join(chunks)
            except httpx.HTTPError as error:
                raise PDFProcessingError("The report PDF is temporarily unavailable.") from error

            if not content or b"%PDF-" not in content[:1024]:
                raise PDFProcessingError("The downloaded report is not a valid PDF.")
            return content
        raise PDFProcessingError("The PDF download used too many redirects.")

    @staticmethod
    def _extract(report_id: str, content: bytes) -> PDFDocument:
        pages: list[PDFPage] = []
        ocr_required: list[int] = []
        try:
            with pymupdf.open(stream=content, filetype="pdf") as document:
                if document.needs_pass:
                    raise PDFProcessingError("The report PDF is password protected.")
                for index, page in enumerate(document):
                    text = page.get_text("text").strip()
                    page_number = index + 1
                    pages.append(PDFPage(page_number=page_number, text=text))
                    if not text:
                        ocr_required.append(page_number)
        except PDFProcessingError:
            raise
        except Exception as error:
            raise PDFProcessingError("The report PDF could not be parsed.") from error
        return PDFDocument(
            report_id=report_id,
            content=content,
            pages=tuple(pages),
            ocr_required_pages=tuple(ocr_required),
        )

    async def _cached(self, report_id: str) -> PDFDocument | None:
        async with self._cache_lock:
            entry = self._cache.get(report_id)
            if entry is None:
                return None
            created_at, document = entry
            if time.monotonic() - created_at > self.settings.pdf_cache_ttl_seconds:
                self._cache.pop(report_id, None)
                self._cache_bytes -= document.estimated_bytes
                return None
            self._cache.move_to_end(report_id)
            return document

    async def _store(self, report_id: str, document: PDFDocument) -> None:
        if document.estimated_bytes > self.settings.pdf_cache_max_bytes:
            return
        async with self._cache_lock:
            previous = self._cache.pop(report_id, None)
            if previous:
                self._cache_bytes -= previous[1].estimated_bytes
            self._cache[report_id] = (time.monotonic(), document)
            self._cache_bytes += document.estimated_bytes
            while self._cache and self._cache_bytes > self.settings.pdf_cache_max_bytes:
                _, (_, evicted) = self._cache.popitem(last=False)
                self._cache_bytes -= evicted.estimated_bytes

    async def get_document(self, report_id: str, pdf_url: str) -> PDFDocument:
        cached = await self._cached(report_id)
        if cached is not None:
            return cached
        async with self._cache_lock:
            lock = self._report_locks.setdefault(report_id, asyncio.Lock())
        async with lock:
            try:
                cached = await self._cached(report_id)
                if cached is not None:
                    return cached
                content = await self._download(pdf_url)
                # PyMuPDF's native runtime is not safe to tear down from a short-lived
                # asyncio worker thread in all supported builds. Extraction remains
                # page-by-page and bounded by the PDF size limit.
                document = self._extract(report_id, content)
                await self._store(report_id, document)
                return document
            finally:
                async with self._cache_lock:
                    if not lock.locked() or self._report_locks.get(report_id) is lock:
                        self._report_locks.pop(report_id, None)

    @staticmethod
    def search(
        document: PDFDocument, query: str, *, limit: int = 20, context: int = 180
    ) -> list[dict[str, int | str]]:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        matches: list[dict[str, int | str]] = []
        for page in document.pages:
            for match in pattern.finditer(page.text):
                start = max(0, match.start() - context)
                end = min(len(page.text), match.end() + context)
                passage = " ".join(page.text[start:end].split())
                matches.append({"page_number": page.page_number, "passage": passage})
                if len(matches) >= limit:
                    return matches
        return matches

